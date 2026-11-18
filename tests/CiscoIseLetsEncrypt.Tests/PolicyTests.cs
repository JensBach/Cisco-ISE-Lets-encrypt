using CiscoIseLetsEncrypt.Ise;
using CiscoIseLetsEncrypt.Tests.Fakes;
using CiscoIseLetsEncrypt.Workflow;

namespace CiscoIseLetsEncrypt.Tests;

public class RenewalPolicyTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 4, 12, 0, 0, TimeSpan.Zero);
    private static readonly string[] Names = ["eap.example.com"];

    private static SystemCertificate Cert(string issuedTo, string expires, string usedBy, bool selfSigned = false, string issuer = "R12") => new()
    {
        Id = Guid.NewGuid().ToString(), FriendlyName = issuedTo, IssuedTo = issuedTo, IssuedBy = issuer,
        ExpirationDate = expires, UsedBy = usedBy, SelfSigned = selfSigned,
    };

    [Fact]
    public void Valid_certificate_with_all_roles_is_not_renewed()
    {
        var certs = new[] { Cert("eap.example.com", "Wed Jan 20 10:00:00 CET 2027", "EAP Authentication, RADIUS DTLS") };

        var d = RenewalPolicy.Evaluate(certs, [IseRole.Eap, IseRole.Dtls], Names, 30, false, Now);

        Assert.False(d.Renew);
    }

    [Theory]
    [InlineData("eap.example.com", "Mon Nov 30 10:00:00 CET 2026", "EAP Authentication, RADIUS DTLS", false, "R12", "expires")]
    [InlineData("ise-17-a.example.com", "Wed Jan 20 10:00:00 CET 2027", "EAP Authentication, RADIUS DTLS", false, "R12", "expected")]
    [InlineData("eap.example.com", "Wed Jan 20 10:00:00 CET 2027", "EAP Authentication", false, "R12", "Dtls: no certificate")]
    [InlineData("eap.example.com", "Wed Jan 20 10:00:00 CET 2027", "EAP Authentication, RADIUS DTLS", true, "R12", "self-signed")]
    [InlineData("eap.example.com", "Wed Jan 20 10:00:00 CET 2027", "EAP Authentication, RADIUS DTLS", false, "(STAGING) Riddling Rhubarb R12", "STAGING")]
    [InlineData("eap.example.com", "garbage", "EAP Authentication, RADIUS DTLS", false, "R12", "cannot parse")]
    public void Renews_when(string issuedTo, string expires, string usedBy, bool selfSigned, string issuer, string expectedReason)
    {
        var certs = new[] { Cert(issuedTo, expires, usedBy, selfSigned, issuer) };

        var d = RenewalPolicy.Evaluate(certs, [IseRole.Eap, IseRole.Dtls], Names, 30, false, Now);

        Assert.True(d.Renew);
        Assert.Contains(d.Reasons, r => r.Contains(expectedReason));
    }

    [Fact]
    public void Staging_certificate_is_accepted_in_test_mode()
    {
        var certs = new[] { Cert("eap.example.com", "Wed Jan 20 10:00:00 CET 2027", "EAP Authentication", issuer: "(STAGING) R12") };

        Assert.False(RenewalPolicy.Evaluate(certs, [IseRole.Eap], Names, 30, true, Now).Renew);
    }
}

public class NodeSelectorTests
{
    private static List<IseNode> Deployment()
    {
        var ise = new FakeIse();
        ise.AddNode("pan", "example.com", "Monitoring");
        ise.AddNode("psn1", "example.com", "Session", "Profiler");
        ise.AddNode("psn2", "example.com", "Session");
        ise.AddNode("pxg", "example.com", "pxGrid");
        return ise.Nodes;
    }

    [Fact]
    public void Eap_selects_policy_service_nodes()
    {
        var nodes = NodeSelector.Select(Deployment(), [], [IseRole.Eap, IseRole.Dtls], "pan.example.com");

        Assert.Equal(["psn1", "psn2"], nodes.Select(n => n.Hostname));
    }

    [Fact]
    public void Admin_selects_all_nodes_with_admin_node_last()
    {
        var nodes = NodeSelector.Select(Deployment(), [], [IseRole.Admin], "pan.example.com");

        Assert.Equal(["psn1", "psn2", "pxg", "pan"], nodes.Select(n => n.Hostname));
    }

    [Fact]
    public void Explicit_nodes_match_fqdn_or_hostname()
    {
        var nodes = NodeSelector.Select(Deployment(), ["PSN2.example.com", "psn1"], [IseRole.Eap], "pan");

        Assert.Equal(["psn2", "psn1"], nodes.Select(n => n.Hostname));
    }
}

public class IseRolesTests
{
    [Fact]
    public void Parses_ise_used_by_string()
    {
        var roles = IseRoles.ParseUsedBy("EAP Authentication, Portal, RADIUS DTLS, TACACS");

        Assert.Equal(new[] { IseRole.Eap, IseRole.Dtls, IseRole.Portal }.ToHashSet(), roles.ToHashSet());
    }

    [Theory]
    [InlineData("EAP", "EAP-AUTH")]
    [InlineData("DTLS", "DTLS-AUTH")]
    [InlineData("EAP,DTLS", "EAP-AUTH")]
    [InlineData("EAP,Portal", "MULTI-USE")]
    [InlineData("Admin", "ADMIN")]
    public void Csr_used_for(string roles, string expected)
    {
        var parsed = roles.Split(',').Select(r => IseRoles.TryParse(r, out var x) ? x : throw new Exception()).ToList();

        Assert.Equal(expected, IseRoles.ToCsrUsedFor(parsed));
    }

    [Theory]
    [InlineData("Wed Oct 08 13:48:22 CEST 2031", "2031-10-08T11:48:22Z")]
    [InlineData("Sat Oct 14 13:06:53 CET 2028", "2028-10-14T12:06:53Z")]
    [InlineData("Tue Feb 3 10:15:30 UTC 2026", "2026-02-03T10:15:30Z")]
    [InlineData("2027-01-01T00:00:00Z", "2027-01-01T00:00:00Z")]
    public void Parses_ise_dates(string value, string expectedUtc)
    {
        Assert.Equal(DateTimeOffset.Parse(expectedUtc), IseDateParser.TryParse(value));
    }
}

public class AcmeRetryTests
{
    private static Certes.AcmeRequestException Error(string type) =>
        new("Fail to load resource", new Certes.Acme.AcmeError { Type = type, Detail = "detail" });

    [Fact]
    public async Task Retries_rate_limited_and_succeeds()
    {
        var calls = 0;
        var result = await CiscoIseLetsEncrypt.Acme.AcmeRetry.RunAsync(() =>
        {
            calls++;
            return calls < 3 ? throw Error("urn:ietf:params:acme:error:rateLimited") : Task.FromResult("ok");
        }, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance, default, [TimeSpan.Zero, TimeSpan.Zero, TimeSpan.Zero]);

        Assert.Equal("ok", result);
        Assert.Equal(3, calls);
    }

    [Fact]
    public async Task Does_not_retry_permanent_errors()
    {
        var calls = 0;
        await Assert.ThrowsAsync<Certes.AcmeRequestException>(() => CiscoIseLetsEncrypt.Acme.AcmeRetry.RunAsync<string>(() =>
        {
            calls++;
            throw Error("urn:ietf:params:acme:error:unauthorized");
        }, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance, default, [TimeSpan.Zero]));

        Assert.Equal(1, calls);
    }
}

public class LetsEncryptCertificatesTests
{
    [Theory]
    [InlineData(false, "RSA", "ISRG Root X1,ISRG Root YR,YR1,YR2,YR3")]
    [InlineData(false, "ECDSA", "ISRG Root X1,ISRG Root X2,ISRG Root YE,YE1,YE2,YE3")]
    [InlineData(true, "RSA", "(STAGING) Pretend Pear X1,(STAGING) Yonder Yam Root YR")]
    public void Embedded_cas_are_valid_and_variants_share_subject_and_key(bool staging, string keyType, string groups)
    {
        var cas = CiscoIseLetsEncrypt.Certificates.LetsEncryptCertificates.For(staging, keyType);

        Assert.Equal(groups.Split(','), cas.Select(c => c.Group).Distinct());
        foreach (var group in cas.GroupBy(c => c.Group))
        {
            Assert.All(group, c => Assert.True(c.Certificate.Extensions.OfType<System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension>().Single().CertificateAuthority));
            Assert.Single(group.Select(c => c.Certificate.Subject).Distinct());
            Assert.Single(group.Select(c => Convert.ToHexString(c.Certificate.PublicKey.EncodedKeyValue.RawData)).Distinct());
        }
    }
}
