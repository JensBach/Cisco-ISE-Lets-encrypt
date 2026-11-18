using CiscoIseLetsEncrypt.Cli;
using CiscoIseLetsEncrypt.Ise;
using CiscoIseLetsEncrypt.Tests.Fakes;
using CiscoIseLetsEncrypt.Workflow;
using Microsoft.Extensions.Logging.Abstractions;

namespace CiscoIseLetsEncrypt.Tests;

public class RenewalWorkflowTests
{
    private const string Name = "eap.example.net";

    private readonly FakeIse _ise = new();
    private readonly FakeAcme _acme = new();
    private readonly FakeDns _dns = new();
    private readonly FakeProbe _probe;
    private readonly AppOptions _options = new()
    {
        AdmNode = "ise-17-a.example.net",
        Roles = [IseRole.Eap, IseRole.Dtls],
        CertificateDns = [Name],
        RadiusSecret = "secret",
        PollInterval = TimeSpan.FromMilliseconds(1),
        VerifyTimeout = TimeSpan.FromMilliseconds(50),
    };

    public RenewalWorkflowTests()
    {
        _probe = new FakeProbe(_ise);
        _ise.Trusted.Add(TestCa.Trusted());
        _ise.AddNode("ise-17-a");
        _ise.AddCertificate("ise-17-a", TestCa.SelfSigned("ise-17-a.example.net", 700), "EAP Authentication, Portal, RADIUS DTLS, TACACS");
        _ise.AddCertificate("ise-17-a", TestCa.SelfSigned("ise-17-a.example.net", 700), "Admin");
    }

    private RenewalWorkflow CreateWorkflow() =>
        new(_options, _ise, _acme, _dns, _dns, new FakeChainResolver(), _probe, TimeProvider.System, NullLogger<RenewalWorkflow>.Instance,
            [TestCa.Known()]);

    [Fact]
    public async Task Replaces_self_signed_certificate_and_moves_roles()
    {
        var results = await CreateWorkflow().RunAsync(CancellationToken.None);

        var result = Assert.Single(results);
        Assert.Equal(NodeOutcome.Renewed, result.Outcome);

        var csr = Assert.Single(_ise.GeneratedCsrs);
        Assert.Equal("ise-17-a", csr.Hostname);
        Assert.Equal(Name, csr.CommonName);
        Assert.Equal([Name], _acme.Orders.Single());

        Assert.Equal([$"_acme-challenge.{Name}"], _dns.Created);
        Assert.Equal(_dns.Created, _dns.Deleted);
        Assert.Single(_ise.Trusted);

        var update = Assert.Single(_ise.RoleUpdates);
        Assert.Equal(new[] { IseRole.Eap, IseRole.Dtls }, update.Roles);

        var newCert = _ise.Certificates["ise-17-a"].Single(c => c.Id == update.Id);
        Assert.Equal(Name, newCert.IssuedTo);
        var old = _ise.Certificates["ise-17-a"].Single(c => c.SelfSigned == true && c.UsedBy!.Contains("Portal"));
        Assert.Equal("Portal, TACACS", old.UsedBy);
        Assert.Contains("Eap@10.0.0.10", _probe.Probed);
    }

    [Fact]
    public async Task Skips_node_when_certificate_is_valid()
    {
        await CreateWorkflow().RunAsync(CancellationToken.None);
        _ise.GeneratedCsrs.Clear();

        var results = await CreateWorkflow().RunAsync(CancellationToken.None);

        Assert.Equal(NodeOutcome.UpToDate, Assert.Single(results).Outcome);
        Assert.Empty(_ise.GeneratedCsrs);
    }

    [Fact]
    public async Task Force_replaces_valid_certificate()
    {
        await CreateWorkflow().RunAsync(CancellationToken.None);
        _options.Force = true;

        var results = await CreateWorkflow().RunAsync(CancellationToken.None);

        Assert.Equal(NodeOutcome.Renewed, Assert.Single(results).Outcome);
        Assert.Equal(2, _ise.GeneratedCsrs.Count);
        Assert.Single(_ise.Trusted);
    }

    [Fact]
    public async Task Failed_acme_validation_cleans_up_dns_and_csr()
    {
        _acme.FailValidation = true;

        var results = await CreateWorkflow().RunAsync(CancellationToken.None);

        var result = Assert.Single(results);
        Assert.Equal(NodeOutcome.Failed, result.Outcome);
        Assert.Contains("unauthorized", result.Message);
        Assert.Equal(_dns.Created, _dns.Deleted);
        Assert.Empty(_dns.Records);
        Assert.Single(_ise.DeletedCsrs);
        Assert.Empty(_ise.Bound);
    }

    [Fact]
    public async Task Csr_refused_by_ise_dns_check_falls_back_to_local_key_and_import()
    {
        _ise.CsrNameResolutionFails = true;

        var results = await CreateWorkflow().RunAsync(CancellationToken.None);

        var result = Assert.Single(results);
        Assert.True(result.Outcome == NodeOutcome.Renewed, result.Message);
        Assert.Empty(_ise.Bound);
        var import = Assert.Single(_ise.Imports).Import;
        Assert.Equal([IseRole.Eap, IseRole.Dtls], import.Roles);
        using (var withKey = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromEncryptedPem(
                   import.Certificate.CertificatePem, import.Certificate.EncryptedPrivateKeyPem, import.Certificate.Password))
            Assert.True(withKey.HasPrivateKey);
        Assert.Empty(_ise.RoleUpdates);
        Assert.Equal(_dns.Created, _dns.Deleted);
        Assert.Equal(Name, _ise.CertificateForRole("ise-17-a", IseRole.Eap)!.GetNameInfo(System.Security.Cryptography.X509Certificates.X509NameType.SimpleName, false));
    }

    [Fact]
    public async Task NoLocalKey_fails_when_ise_refuses_the_csr()
    {
        _ise.CsrNameResolutionFails = true;
        _options.NoLocalKey = true;

        var results = await CreateWorkflow().RunAsync(CancellationToken.None);

        Assert.Equal(NodeOutcome.Failed, Assert.Single(results).Outcome);
        Assert.Empty(_acme.Orders);
        Assert.Empty(_ise.Imports);
    }

    [Fact]
    public async Task Csr_with_unexpected_names_is_rejected_before_ordering()
    {
        _ise.ExtraSanInCsr.Add("evil.example.com");

        var results = await CreateWorkflow().RunAsync(CancellationToken.None);

        Assert.Equal(NodeOutcome.Failed, Assert.Single(results).Outcome);
        Assert.Empty(_acme.Orders);
        Assert.Single(_ise.DeletedCsrs);
    }

    [Fact]
    public async Task Fails_when_service_keeps_presenting_old_certificate()
    {
        _probe.Snapshot("ise-17-a");
        _probe.StaleServices = true;

        var results = await CreateWorkflow().RunAsync(CancellationToken.None);

        var result = Assert.Single(results);
        Assert.Equal(NodeOutcome.Failed, result.Outcome);
        Assert.Contains("does not present the new certificate", result.Message);
    }

    [Fact]
    public async Task Eap_role_without_radius_secret_fails_before_any_change()
    {
        _options.RadiusSecret = null;

        await Assert.ThrowsAsync<InvalidOperationException>(() => CreateWorkflow().RunAsync(CancellationToken.None));
        Assert.Empty(_ise.GeneratedCsrs);
    }

    [Fact]
    public async Task Failing_radius_check_stops_before_any_change()
    {
        _probe.FailRadius = true;

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => CreateWorkflow().RunAsync(CancellationToken.None));

        Assert.Contains("RADIUS check failed", ex.Message);
        Assert.Empty(_ise.GeneratedCsrs);
        Assert.Empty(_acme.Orders);
        Assert.Empty(_dns.Created);
    }

    [Fact]
    public async Task Missing_write_access_stops_before_any_change()
    {
        _ise.WriteAccess = false;

        await Assert.ThrowsAsync<InvalidOperationException>(() => CreateWorkflow().RunAsync(CancellationToken.None));
        Assert.Empty(_ise.GeneratedCsrs);
    }

    [Fact]
    public async Task Untrusted_lets_encrypt_ca_stops_before_any_change()
    {
        _ise.Trusted.Clear();
        _options.DryRun = true;

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => CreateWorkflow().RunAsync(CancellationToken.None));

        Assert.Contains("Test ACME Root", ex.Message);
        Assert.Empty(_ise.GeneratedCsrs);
    }

    [Fact]
    public async Task Ca_trusted_under_another_variant_is_accepted_by_subject()
    {
        _ise.Trusted.Clear();
        _ise.Trusted.Add(new TrustedCertificate { Id = "x", FriendlyName = "cross-signed", Subject = "CN = test acme root", Sha256Fingerprint = "00" });
        _options.DryRun = true;

        var results = await CreateWorkflow().RunAsync(CancellationToken.None);

        Assert.Equal(NodeOutcome.WouldRenew, Assert.Single(results).Outcome);
    }

    [Fact]
    public async Task Untrusted_ca_in_issued_chain_fails_before_binding_and_cleans_up()
    {
        var workflow = new RenewalWorkflow(_options, _ise, _acme, _dns, _dns, new FakeChainResolver(), _probe, TimeProvider.System,
            NullLogger<RenewalWorkflow>.Instance, []);
        _ise.Trusted.Clear();

        var result = Assert.Single(await workflow.RunAsync(CancellationToken.None));

        Assert.Equal(NodeOutcome.Failed, result.Outcome);
        Assert.Contains("Test ACME Root", result.Message);
        Assert.Empty(_ise.Bound);
        Assert.Single(_ise.DeletedCsrs);
        Assert.Equal(_dns.Created, _dns.Deleted);
    }

    [Fact]
    public async Task Dry_run_changes_nothing()
    {
        _options.DryRun = true;
        _options.KeepOldCertificates = false;
        _ise.AddNode("ise-17-b");
        _ise.AddCertificate("ise-17-b", TestCa.SelfSigned("ise-17-b.example.net", 700), "EAP Authentication, RADIUS DTLS");

        var results = await CreateWorkflow().RunAsync(CancellationToken.None);

        Assert.All(results, r => Assert.Equal(NodeOutcome.WouldRenew, r.Outcome));
        Assert.Equal(2, results.Count);
        Assert.Empty(_ise.GeneratedCsrs);
        Assert.Empty(_acme.Orders);
        Assert.Empty(_dns.Created);
        Assert.Empty(_ise.RoleUpdates);
        Assert.Empty(_ise.Exports);
        Assert.Empty(_ise.Imports);
        Assert.Empty(_ise.DeletedCertificates);
    }

    [Fact]
    public async Task Same_certificate_is_exported_to_the_other_nodes()
    {
        _ise.AddNode("ise-17-b");
        _ise.AddCertificate("ise-17-b", TestCa.SelfSigned("ise-17-b.example.net", 700), "EAP Authentication, RADIUS DTLS, Admin");

        var results = await CreateWorkflow().RunAsync(CancellationToken.None);

        Assert.Equal(2, results.Count);
        Assert.All(results, r => Assert.Equal(NodeOutcome.Renewed, r.Outcome));
        var csr = Assert.Single(_ise.GeneratedCsrs);
        Assert.Single(_acme.Orders);
        var export = Assert.Single(_ise.Exports);
        Assert.Equal(csr.Hostname, export.Host);
        var import = Assert.Single(_ise.Imports);
        Assert.NotEqual(csr.Hostname, import.Host);
        Assert.Equal(new[] { IseRole.Eap, IseRole.Dtls }, import.Import.Roles);

        var source = _ise.CertificateForRole(csr.Hostname, IseRole.Eap)!;
        var target = _ise.CertificateForRole(import.Host, IseRole.Eap)!;
        Assert.Equal(source.Thumbprint, target.Thumbprint);
        Assert.Equal(Name, target.GetNameInfo(System.Security.Cryptography.X509Certificates.X509NameType.SimpleName, false));
        Assert.Contains($"Eap@{_ise.Nodes.Single(n => n.Hostname == import.Host).IpAddress}", _probe.Probed);
    }

    [Fact]
    public async Task Old_certificates_are_kept_by_default()
    {
        await CreateWorkflow().RunAsync(CancellationToken.None);
        _options.Force = true;

        await CreateWorkflow().RunAsync(CancellationToken.None);

        Assert.Empty(_ise.DeletedCertificates);
        Assert.Equal(4, _ise.Certificates["ise-17-a"].Count);
    }

    [Fact]
    public async Task DeleteOldCertificates_deletes_only_certificates_no_longer_in_use()
    {
        await CreateWorkflow().RunAsync(CancellationToken.None);
        var previous = _ise.Certificates["ise-17-a"].Single(c => c.IssuedTo == Name);
        _options.Force = true;
        _options.KeepOldCertificates = false;

        await CreateWorkflow().RunAsync(CancellationToken.None);

        var deleted = Assert.Single(_ise.DeletedCertificates);
        Assert.Equal(previous.Id, deleted.Id);
        Assert.Contains(_ise.Certificates["ise-17-a"], c => c.UsedBy == "Portal, TACACS");
        Assert.Contains(_ise.Certificates["ise-17-a"], c => c.UsedBy == "Admin");
    }

    [Fact]
    public async Task Admin_role_is_verified_over_https()
    {
        _options.Roles = [IseRole.Admin];

        var results = await CreateWorkflow().RunAsync(CancellationToken.None);

        Assert.Equal(NodeOutcome.Renewed, Assert.Single(results).Outcome);
        Assert.Equal(["Admin@ise-17-a.example.net"], _probe.Probed);
        Assert.Equal("ADMIN", IseRoles.ToCsrUsedFor(_ise.GeneratedCsrs.Single().Roles));
    }

    [Fact]
    public async Task Unknown_node_fails_the_run()
    {
        _options.Nodes = ["ise-99-z.example.net"];

        await Assert.ThrowsAsync<InvalidOperationException>(() => CreateWorkflow().RunAsync(CancellationToken.None));
    }
}
