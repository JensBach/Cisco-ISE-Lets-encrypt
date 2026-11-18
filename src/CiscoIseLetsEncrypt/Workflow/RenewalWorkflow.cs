using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CiscoIseLetsEncrypt.Acme;
using CiscoIseLetsEncrypt.Certificates;
using CiscoIseLetsEncrypt.Cli;
using CiscoIseLetsEncrypt.Dns;
using CiscoIseLetsEncrypt.Ise;
using CiscoIseLetsEncrypt.Verification;
using Microsoft.Extensions.Logging;

namespace CiscoIseLetsEncrypt.Workflow;

public enum NodeOutcome { UpToDate, Renewed, WouldRenew, Failed }

public sealed record NodeResult(string Node, NodeOutcome Outcome, string Message);

public sealed class RenewalWorkflow(
    AppOptions options,
    IIseClient ise,
    IAcmeService acme,
    IDnsChallengeClient dns,
    IDnsPropagationChecker propagation,
    IIssuerChainResolver chainResolver,
    ICertificateProbe probe,
    TimeProvider time,
    ILogger<RenewalWorkflow> log,
    IReadOnlyList<KnownCa>? requiredCas = null)
{
    private readonly IReadOnlyList<KnownCa> _requiredCas = requiredCas ?? LetsEncryptCertificates.For(options.AcmeTest, options.KeyType);

    private static readonly IseRole[] ExclusiveRoles = [IseRole.Admin, IseRole.Eap, IseRole.Dtls, IseRole.PxGrid, IseRole.Ims, IseRole.Saml];

    private sealed record NodeState(IseNode Node, IReadOnlyList<SystemCertificate> Certificates, RenewalDecision Decision, IReadOnlySet<string> PreviousHolderIds);

    private sealed record IssuedOnNode(SystemCertificate Installed, string Fingerprint, DateTime NotAfterUtc);

    public async Task<IReadOnlyList<NodeResult>> RunAsync(CancellationToken ct)
    {
        log.LogInformation("ACME server: {Server}{Test}", acme.ServerDescription, options.AcmeTest ? " (TEST / staging)" : "");
        log.LogInformation("Roles: {Roles}; certificate names: {Names}", IseRoles.Format(options.Roles), string.Join(", ", options.CertificateDns));
        if (options.DryRun)
            log.LogWarning("DRY RUN – nothing will be changed on ISE, Let's Encrypt or DNS.");

        var deployment = await ise.GetNodesAsync(ct);
        var nodes = NodeSelector.Select(deployment, options.Nodes, options.Roles, options.AdmNode);

        Step(null, "0a", "Checking RADIUS access (EAP-PEAP) to the nodes");
        await CheckRadiusAsync(nodes, ct);

        Step(null, "0b", "Checking ISE API access and permissions");
        await CheckPermissionsAsync(deployment, ct);

        Step(null, "0c", "Checking that ISE trusts the Let's Encrypt CA certificates");
        await CheckCaTrustAsync(ct);

        Step(null, "1", $"ISE cluster overview from admin node {options.AdmNode}");
        await LogClusterOverviewAsync(deployment, ct);

        Step(null, "2", "Identifying nodes that need certificate updates for the requested roles");
        if (nodes.Count == 0)
        {
            log.LogWarning("No nodes in the deployment run services for roles {Roles}.", IseRoles.Format(options.Roles));
            return [];
        }
        foreach (var n in nodes.Where(n => !NodeSelector.IsRelevant(n, options.Roles)))
            log.LogWarning("Node {Node} does not run services used by roles {Roles} – updating anyway because it was requested.",
                n, IseRoles.Format(options.Roles));
        log.LogInformation("Nodes selected: {Nodes}", string.Join(", ", nodes));
        if (nodes.Count > 1)
            log.LogInformation("The same certificate is used on all selected nodes: it is issued on {Source} and exported with its " +
                               "(encrypted) private key to {Targets}.", nodes[0], string.Join(", ", nodes.Skip(1)));

        var names = options.CertificateDns.ToList();
        if (options.IncludeNodeFqdn)
            names.AddRange(nodes.Select(n => n.Fqdn.ToLowerInvariant()).Where(f => f.Length > 0 && !names.Contains(f, StringComparer.OrdinalIgnoreCase)));

        var results = new List<NodeResult>();
        var states = new List<NodeState>();
        foreach (var node in nodes)
        {
            try
            {
                states.Add(await InspectNodeAsync(node, names, ct));
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                results.Add(Fail(node, ex));
            }
        }

        if (states.Count > 0)
            results.AddRange(await RenewAsync(states, names, ct));

        foreach (var r in results)
            log.LogInformation("Result {Node}: {Outcome} {Message}", r.Node, r.Outcome, r.Message);
        return results;
    }

    private async Task<IReadOnlyList<NodeResult>> RenewAsync(List<NodeState> states, List<string> names, CancellationToken ct)
    {
        var shared = SharedCertificateReason(states);
        if (shared is not null)
            log.LogInformation("{Reason}", shared);

        if (!states.Any(s => s.Decision.Renew) && shared is null && !options.Force)
        {
            log.LogInformation("Certificates are valid and correctly assigned – nothing to do (use -Force to replace anyway).");
            return states.Select(s => new NodeResult(s.Node.ToString(), NodeOutcome.UpToDate, "Certificate is up to date")).ToList();
        }
        if (!states.Any(s => s.Decision.Renew) && shared is null)
            log.LogInformation("-Force specified – replacing certificate anyway.");

        if (options.DryRun)
            return LogDryRunPlan(states, names);

        var results = new List<NodeResult>();
        var source = states[0];
        IssuedOnNode issued;
        try
        {
            issued = await IssueOnNodeAsync(source.Node, names, ct);
            // A bound certificate has no roles yet; an imported one (local key fallback) got them with the import.
            await ActivateAsync(source, issued, assignRoles: options.Roles.Any(r => !issued.Installed.Roles.Contains(r)), ct);
            results.Add(new NodeResult(source.Node.ToString(), NodeOutcome.Renewed,
                $"Installed {issued.Fingerprint}, expires {issued.NotAfterUtc:yyyy-MM-dd}"));
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            results.Add(Fail(source.Node, ex));
            results.AddRange(states.Skip(1).Select(s =>
                new NodeResult(s.Node.ToString(), NodeOutcome.Failed, $"Not updated – issuing the certificate on {source.Node} failed")));
            return results;
        }

        ExportedCertificate? exported = null;
        foreach (var target in states.Skip(1))
        {
            try
            {
                exported ??= await ExportAsync(source.Node, issued, ct);
                await DistributeAsync(source.Node, target, issued, exported, ct);
                results.Add(new NodeResult(target.Node.ToString(), NodeOutcome.Renewed,
                    $"Installed {issued.Fingerprint} (same certificate as {source.Node}), expires {issued.NotAfterUtc:yyyy-MM-dd}"));
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                results.Add(Fail(target.Node, ex));
            }
        }
        return results;
    }

    private NodeResult Fail(IseNode node, Exception ex)
    {
        log.LogError(ex, "[{Node}] FAILED: {Error}", node, ex.Message);
        return new NodeResult(node.ToString(), NodeOutcome.Failed, ex.Message);
    }

    /// <summary>With several nodes all of them must present the same certificate for the roles.</summary>
    private string? SharedCertificateReason(IReadOnlyList<NodeState> states)
    {
        if (states.Count < 2)
            return null;
        var fingerprints = states
            .SelectMany(s => s.Certificates.Where(c => c.Roles.Overlaps(options.Roles)))
            .Select(c => CertificateUtil.NormalizeFingerprint(c.Sha256Fingerprint))
            .Distinct()
            .ToList();
        return fingerprints.Count > 1 || states.Any(s => !s.Certificates.Any(c => c.Roles.Overlaps(options.Roles)))
            ? "The selected nodes do not share the same certificate for the roles – one new certificate will be installed on all of them."
            : null;
    }

    private async Task CheckRadiusAsync(IReadOnlyList<IseNode> nodes, CancellationToken ct)
    {
        if (!options.Roles.Contains(IseRole.Eap))
        {
            log.LogInformation("EAP is not among the roles – RADIUS check not needed.");
            return;
        }
        if (options.SkipVerification)
        {
            log.LogWarning("RADIUS check skipped (-SkipVerification).");
            return;
        }
        if (string.IsNullOrEmpty(options.RadiusSecret))
            throw new InvalidOperationException("The EAP role requires a RADIUS shared secret (-RadiusSecret) for the RADIUS check.");

        var failures = new List<string>();
        foreach (var node in nodes)
        {
            var address = node.IpAddress ?? node.ProbeAddress;
            try
            {
                var cert = await probe.GetEapCertificateAsync(address, options.RadiusPort, options.RadiusSecret, options.RadiusIdentity, ct);
                log.LogInformation("[{Node}] RADIUS {Address}:{Port} answers; EAP-PEAP presents {Subject} (issuer {Issuer}, expires {NotAfter:yyyy-MM-dd}) ✔",
                    node, address, options.RadiusPort, cert.Subject, cert.Issuer, cert.NotAfter);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                log.LogError("[{Node}] RADIUS {Address}:{Port} check failed: {Error}", node, address, options.RadiusPort, ex.Message);
                failures.Add($"{node}: {ex.Message}");
            }
        }
        if (failures.Count > 0)
            throw new InvalidOperationException(
                "RADIUS check failed – nothing has been changed. This host (its source IP as seen by ISE, mind VPN/NAT) must be a " +
                "Network Device in ISE with the RADIUS shared secret, and PEAP must be allowed. " + string.Join("; ", failures));
    }

    private async Task CheckPermissionsAsync(IReadOnlyList<IseNode> deployment, CancellationToken ct)
    {
        log.LogInformation("  OpenAPI login and read deployment nodes ({Count}) ✔", deployment.Count);
        var trusted = await ise.GetTrustedCertificatesAsync(ct);
        log.LogInformation("  Read trusted certificates ({Count}) ✔", trusted.Count);
        if (!await ise.HasWriteAccessAsync(ct))
            throw new InvalidOperationException(
                "The ISE API user can read but not change certificates. Add it to the ERS Admin or Super Admin group.");
        log.LogInformation("  Write access to certificates ✔ (checked with an invalid request that ISE rejects – nothing changed)");

    }

    private async Task CheckCaTrustAsync(CancellationToken ct)
    {
        var trusted = await ise.GetTrustedCertificatesAsync(ct);
        var missing = new List<KnownCa>();
        foreach (var group in _requiredCas.GroupBy(c => c.Group))
        {
            var variants = group.ToList();
            var match = variants.Select(v => CaTrust.FindTrusted(v.Certificate, trusted)).FirstOrDefault(t => t is not null);
            var kind = variants[0].Kind;
            if (match is not null)
                log.LogInformation("  {Kind} '{Ca}' trusted as '{Name}' ✔", kind, group.Key, match.FriendlyName);
            else if (kind == CaKind.Backup)
                log.LogWarning("  Backup intermediate '{Ca}' is not trusted – not used by Let's Encrypt today, but install it to be ready.", group.Key);
            else
            {
                log.LogError("  {Kind} '{Ca}' is NOT trusted by ISE", kind, group.Key);
                missing.Add(variants[0]);
            }
        }
        if (options.AcmeTest)
            log.LogInformation("  Let's Encrypt staging publishes no intermediates – they are checked after issuance (step 6).");
        if (missing.Count == 0)
            return;

        LogCertificatesToInstall(missing.Select(m => (m.Label, m.Certificate, (string?)m.Url)));
        throw new InvalidOperationException(
            $"ISE does not trust {missing.Count} Let's Encrypt CA certificate(s): {string.Join(", ", missing.Select(m => m.Label))}. " +
            "Nothing has been changed. Install them in ISE (see the log above) and run again.");
    }

    private void LogCertificatesToInstall(IEnumerable<(string Name, X509Certificate2 Certificate, string? Url)> certificates)
    {
        log.LogError("Install these certificates in the ISE admin GUI: Administration > System > Certificates > Trusted Certificates > Import, " +
                     "with 'Trust for authentication within ISE' checked (not 'Trust for client authentication'). Use the self-signed " +
                     "root when both a self-signed and a cross-signed version exist.");
        foreach (var (name, cert, url) in certificates)
        {
            log.LogError("----- {Name} -----\n  Subject:  {Subject}\n  Issuer:   {Issuer}\n  Valid:    {From:yyyy-MM-dd} – {To:yyyy-MM-dd}\n" +
                         "  SHA-256:  {Fp}\n  Download: {Url}\n{Pem}",
                name, cert.Subject, cert.Issuer, cert.NotBefore, cert.NotAfter, CertificateUtil.Sha256(cert),
                url ?? "(from the Let's Encrypt certificate chain)", CertificateUtil.ToPem(cert).TrimEnd());
        }
    }

    private async Task LogClusterOverviewAsync(IReadOnlyList<IseNode> deployment, CancellationToken ct)
    {
        foreach (var n in deployment)
        {
            log.LogInformation("Node {Node} ({Ip}) roles=[{Roles}] services=[{Services}] status={Status}",
                n, n.IpAddress, string.Join(",", n.Roles), string.Join(",", n.Services), n.NodeStatus);
            IReadOnlyList<SystemCertificate> certificates;
            try
            {
                certificates = await ise.GetSystemCertificatesAsync(n.Hostname, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                log.LogWarning("  Could not read system certificates of {Node}: {Error}", n, ex.Message);
                continue;
            }
            foreach (var c in certificates)
                log.LogInformation("    [{UsedBy}] '{Name}' CN={CN} issuer={Issuer} expires={Expires}",
                    c.IsUnused ? "Not in use" : c.UsedBy, c.FriendlyName, c.IssuedTo, c.IssuedBy, c.ExpiresUtc?.ToString("yyyy-MM-dd") ?? c.ExpirationDate);
        }
    }

    private async Task<NodeState> InspectNodeAsync(IseNode node, IReadOnlyCollection<string> names, CancellationToken ct)
    {
        Step(node, "2a", "Reading system certificates and their service/portal mappings");
        var certificates = await ise.GetSystemCertificatesAsync(node.Hostname, ct);
        foreach (var role in options.Roles.OrderBy(r => r))
        {
            var holders = certificates.Where(c => c.Roles.Contains(role)).ToList();
            log.LogInformation("[{Node}]   {Role}: {Holders}", node, role, holders.Count == 0 ? "no certificate" : string.Join("; ", holders));
        }
        foreach (var c in certificates.Where(c => !string.IsNullOrEmpty(c.GroupTag)))
            log.LogInformation("[{Node}]   portal group tag '{Tag}' ('{Cert}') used by portals: {Portals}",
                node, c.GroupTag, c.FriendlyName, c.PortalsUsingTheTag);

        Step(node, "2b", "Checking whether the certificate must be replaced");
        var decision = RenewalPolicy.Evaluate(certificates, options.Roles, names, options.RenewBeforeDays, options.AcmeTest, time.GetUtcNow());
        foreach (var reason in decision.Reasons)
            log.LogInformation("[{Node}]   {Reason}", node, reason);
        if (!decision.Renew)
            log.LogInformation("[{Node}]   Certificate is valid and correctly assigned.", node);
        var holderIds = certificates.Where(c => c.Roles.Overlaps(options.Roles)).Select(c => c.Id).ToHashSet();
        return new NodeState(node, certificates, decision, holderIds);
    }

    private IReadOnlyList<NodeResult> LogDryRunPlan(IReadOnlyList<NodeState> states, IReadOnlyList<string> names)
    {
        var source = states[0].Node;
        var test = options.AcmeTest ? "-STAGING" : "";
        log.LogWarning("DRY RUN – the following would be done (nothing has been changed):");
        log.LogInformation("  3. Generate a CSR on {Node}: usage {Usage}, {KeyType} {KeyLength}/{Digest}, CN={CN}, SAN={San} (private key stays on ISE)",
            source, IseRoles.ToCsrUsedFor(options.Roles), options.KeyType, options.KeyLength, options.DigestType, names[0], string.Join(",", names));
        log.LogInformation("     {Fallback}", options.NoLocalKey
            ? "If ISE refuses the CSR (name does not resolve to the node), the run fails (-NoLocalKey)."
            : "If ISE refuses the CSR (name does not resolve to the node), the key and CSR are generated here (WARNING) and the certificate is imported with its encrypted key.");
        log.LogInformation("  4. Order the certificate from {Server}; create TXT {Records} via {Dns} (unless Let's Encrypt has a cached validation)",
            acme.ServerDescription, string.Join(", ", names.Select(n => "_acme-challenge." + n)), options.DnsDescription);
        log.LogInformation("  5. Wait for the TXT record on {Resolvers}, validate and finalize the order with the ISE CSR",
            string.Join(", ", options.DnsResolvers));
        log.LogInformation("  6. Check that ISE trusts the issued chain, bind as '{CN} LetsEncrypt{Test} <date time>' on {Node}",
            names[0], test, source);
        log.LogInformation("  7. Delete the TXT record(s)");
        foreach (var s in states.Skip(1))
            log.LogInformation("  6. {Target}: export the certificate with its encrypted private key from {Source} and import it with the roles",
                s.Node, source);
        foreach (var s in states)
        {
            var holders = s.Certificates.Where(c => c.Roles.Overlaps(options.Roles)).ToList();
            log.LogInformation("  8. {Node}: assign {Roles} to the new certificate, taking them from: {Holders}",
                s.Node, IseRoles.Format(options.Roles), holders.Count == 0 ? "(none)" : string.Join("; ", holders.Select(h => $"'{h.FriendlyName}' [{h.UsedBy}]")));
            log.LogInformation("  9/10. {Node}: verify the services and the installation", s.Node);
            foreach (var h in holders)
            {
                var remaining = RemainingUsages(h);
                log.LogInformation("  11. {Node}: '{Cert}' {Action}", s.Node, h.FriendlyName,
                    remaining.Count > 0 ? $"keeps {string.Join(", ", remaining)} and is kept"
                    : options.KeepOldCertificates ? "would no longer be used – kept (default)"
                    : "would no longer be used – deleted (-DeleteOldCertificates)");
            }
        }
        return states.Select(s => new NodeResult(s.Node.ToString(), NodeOutcome.WouldRenew, "Dry run – certificate would be replaced")).ToList();
    }

    /// <summary>Usages (incl. ones this program does not manage, e.g. TACACS) a certificate keeps after the roles move.</summary>
    private List<string> RemainingUsages(SystemCertificate certificate)
    {
        var remaining = (certificate.UsedBy ?? "")
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(u => !u.Equals("Not in use", StringComparison.OrdinalIgnoreCase))
            .Where(u => !(IseRoles.TryParse(u, out var r) && options.Roles.Contains(r)))
            .ToList();
        if (!string.IsNullOrWhiteSpace(certificate.PortalsUsingTheTag) && !options.Roles.Contains(IseRole.Portal))
            remaining.Add("portal group tag");
        return remaining;
    }

    /// <summary>Steps 3–7: CSR on ISE, ACME DNS-01, bind. Returns the bound certificate (no roles yet).</summary>
    private async Task<IssuedOnNode> IssueOnNodeAsync(IseNode node, IReadOnlyList<string> names, CancellationToken ct)
    {
        Step(node, "3", "Generating certificate signing request on the ISE node (private key stays on ISE)");
        string csrId;
        try
        {
            csrId = await ise.GenerateCsrAsync(new CsrRequest(node.Hostname, options.Roles, names[0], names,
                options.KeyType, options.KeyLength, options.DigestType, options.PortalGroupTag), ct);
        }
        catch (IseCsrNameResolutionException ex) when (!options.NoLocalKey)
        {
            return await IssueWithLocalKeyAsync(node, names, ex, ct);
        }
        log.LogInformation("[{Node}] CSR created with id {CsrId}", node, csrId);

        var bound = false;
        string fingerprint;
        DateTime notAfter;
        try
        {
            var csrPem = await ise.ExportCsrAsync(node.Hostname, csrId, ct);
            var csr = CertificateUtil.ParseCsr(csrPem);
            log.LogInformation("[{Node}] CSR subject CN={CN}, DNS SANs={Sans}", node, csr.CommonName, string.Join(", ", csr.DnsNames));
            var unexpected = csr.AllNames.Except(names, StringComparer.OrdinalIgnoreCase).ToList();
            if (unexpected.Count > 0)
                throw new InvalidOperationException($"CSR from ISE contains unexpected names: {string.Join(", ", unexpected)}");

            (fingerprint, notAfter) = await OrderAndInstallAsync(node, csr, async (issued, friendlyName) =>
            {
                await ise.BindCertificateAsync(new BindRequest(node.Hostname, csrId, issued.LeafPem, friendlyName), ct);
                bound = true;
                log.LogInformation("[{Node}] Certificate bound to CSR {CsrId} as '{Name}'", node, csrId, friendlyName);
            }, ct);
        }
        catch when (!bound)
        {
            try
            {
                await ise.DeleteCsrAsync(node.Hostname, csrId, CancellationToken.None);
                log.LogInformation("[{Node}] Deleted unused CSR {CsrId}", node, csrId);
            }
            catch (Exception ex)
            {
                log.LogWarning("[{Node}] Could not delete CSR {CsrId}: {Error}", node, csrId, ex.Message);
            }
            throw;
        }

        var installed = await FindByFingerprintAsync(node, fingerprint, ct)
                        ?? throw new InvalidOperationException($"Bound certificate {fingerprint} not found in system certificates of {node}");
        return new IssuedOnNode(installed, fingerprint, notAfter);
    }

    /// <summary>
    /// Fallback when ISE refuses the CSR because a name does not resolve to the node: the key and CSR are made here
    /// (memory only) and the certificate is imported with its encrypted private key and the roles.
    /// </summary>
    private async Task<IssuedOnNode> IssueWithLocalKeyAsync(IseNode node, IReadOnlyList<string> names, IseCsrNameResolutionException reason,
        CancellationToken ct)
    {
        log.LogWarning("[{Node}] ISE refused to generate the CSR: the certificate name(s) {Names} do not resolve (in ISE's DNS) to the node's IP address.",
            node, string.Join(", ", names));
        log.LogDebug("[{Node}] ISE response: {Error}", node, reason.Message);
        log.LogWarning("[{Node}] WARNING: generating the private key and CSR in this program instead ({KeyType} {KeyLength}/{Digest}). " +
                       "The key exists only in memory, is sent encrypted to ISE and is never written to disk. " +
                       "Create a DNS A record for the name pointing to the node (or use -NoLocalKey) to keep the key on ISE.",
            node, options.KeyType, options.KeyLength, options.DigestType);

        var local = CertificateUtil.CreateLocalKeyCsr(names, options.KeyType, options.KeyLength, options.DigestType);
        log.LogInformation("[{Node}] Local CSR subject CN={CN}, DNS SANs={Sans}", node, local.Csr.CommonName, string.Join(", ", local.Csr.DnsNames));

        var (fingerprint, notAfter) = await OrderAndInstallAsync(node, local.Csr, async (issued, friendlyName) =>
        {
            if (options.Roles.Contains(IseRole.Admin))
                log.LogWarning("[{Node}] Admin role change restarts the ISE application server on this node.", node);
            await ise.ImportSystemCertificateAsync(node, new SystemCertificateImport(friendlyName,
                new ExportedCertificate(issued.LeafPem, local.EncryptedPrivateKeyPem, local.Password), options.Roles, options.PortalGroupTag), ct);
            log.LogInformation("[{Node}] Certificate imported with its private key as '{Name}', roles {Roles}",
                node, friendlyName, IseRoles.Format(options.Roles));
        }, ct);

        var installed = await FindByFingerprintAsync(node, fingerprint, ct)
                        ?? throw new InvalidOperationException($"Imported certificate {fingerprint} not found in system certificates of {node}");
        return new IssuedOnNode(installed, fingerprint, notAfter);
    }

    /// <summary>Steps 4–7: ACME order with DNS-01 for <paramref name="csr"/>, chain check, install, TXT cleanup.</summary>
    private async Task<(string Fingerprint, DateTime NotAfterUtc)> OrderAndInstallAsync(IseNode node, CsrDetails csr,
        Func<IssuedCertificate, string, Task> install, CancellationToken ct)
    {
        var order = await acme.NewOrderAsync(csr.AllNames, ct);
        var challenges = await order.GetPendingDnsChallengesAsync(ct);
        var createdRecords = new List<string>();
        try
        {
            Step(node, "4", $"Creating {challenges.Count} DNS-01 challenge record(s)");
            foreach (var ch in challenges)
            {
                await dns.CreateTxtRecordAsync(ch.RecordName, ch.TxtValue, ct);
                createdRecords.Add(ch.RecordName);
            }

            Step(node, "5", "Validating DNS-01 challenge(s)");
            foreach (var ch in challenges)
            {
                if (!await propagation.WaitForTxtRecordAsync(ch.RecordName, ch.TxtValue, options.DnsPropagationTimeout, ct))
                    log.LogWarning("[{Node}] TXT {Record} not seen on all resolvers – asking the CA to validate anyway.", node, ch.RecordName);
            }
            await order.ValidateAsync(ct);
            var issued = await order.FinalizeAsync(csr.Der, ct);
            var leaf = X509Certificate2.CreateFromPem(issued.LeafPem);
            log.LogInformation("[{Node}] Certificate issued: subject={Subject} issuer={Issuer} notAfter={NotAfter:u} sha256={Fp}",
                node, leaf.Subject, leaf.Issuer, leaf.NotAfter.ToUniversalTime(), CertificateUtil.Sha256(leaf));

            Step(node, "6", "Installing the new certificate on the ISE node");
            var issuers = issued.IssuerPems.Select(p => X509Certificate2.CreateFromPem(p)).ToList();
            await EnsureChainTrustedAsync(node, leaf, issuers, ct);
            var friendlyName = $"{csr.CommonName} LetsEncrypt{(options.AcmeTest ? "-STAGING" : "")} {time.GetUtcNow():yyyy-MM-dd HHmm}";
            await install(issued, friendlyName);
            return (CertificateUtil.Sha256(leaf), leaf.NotAfter.ToUniversalTime());
        }
        finally
        {
            Step(node, "7", "Removing DNS-01 challenge record(s)");
            foreach (var record in createdRecords)
            {
                try
                {
                    await dns.DeleteTxtRecordAsync(record, CancellationToken.None);
                }
                catch (Exception ex)
                {
                    log.LogWarning("[{Node}] Failed to delete TXT {Record}: {Error}", node, record, ex.Message);
                }
            }
        }
    }

    /// <summary>Steps 8–11 on a node where the new certificate is installed.</summary>
    private async Task ActivateAsync(NodeState state, IssuedOnNode issued, bool assignRoles, CancellationToken ct)
    {
        var node = state.Node;
        var installed = await FindByFingerprintAsync(node, issued.Fingerprint, ct)
                        ?? throw new InvalidOperationException($"New certificate {issued.Fingerprint} not found in system certificates of {node}");
        if (assignRoles)
        {
            Step(node, "8", $"Assigning roles {IseRoles.Format(options.Roles)} to certificate '{installed.FriendlyName}'");
            if (options.Roles.Contains(IseRole.Admin))
                log.LogWarning("[{Node}] Admin role change restarts the ISE application server on this node.", node);
            await ise.UpdateSystemCertificateRolesAsync(node.Hostname, installed, options.Roles, options.PortalGroupTag, ct);
        }

        Step(node, "9", "Verifying that the services present the new certificate");
        await VerifyServicesAsync(node, issued.Fingerprint, ct);

        Step(node, "10", "Verifying the certificate installation through the ISE API");
        await VerifyInstallationAsync(node, issued.Fingerprint, ct);

        Step(node, "11", "Handling the previous certificate(s)");
        await HandleOldCertificatesAsync(state, installed.Id, ct);

        log.LogInformation("[{Node}] Certificate replaced successfully (expires {NotAfter:u}).", node, issued.NotAfterUtc);
    }

    private async Task<ExportedCertificate> ExportAsync(IseNode source, IssuedOnNode issued, CancellationToken ct)
    {
        // Alphanumeric, as required by ISE. Only kept in memory for the duration of the run.
        var password = RandomNumberGenerator.GetString("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789", 40);
        log.LogInformation("[{Node}] Exporting certificate '{Name}' with its private key (encrypted, kept in memory only)",
            source, issued.Installed.FriendlyName);
        var exported = await ise.ExportSystemCertificateAsync(source.Hostname, issued.Installed.Id, password, ct);
        var fp = CertificateUtil.Sha256(X509Certificate2.CreateFromPem(exported.CertificatePem));
        if (fp != issued.Fingerprint)
            throw new InvalidOperationException($"Exported certificate {fp} does not match the issued certificate {issued.Fingerprint}.");
        return exported;
    }

    private async Task DistributeAsync(IseNode source, NodeState target, IssuedOnNode issued, ExportedCertificate exported, CancellationToken ct)
    {
        var node = target.Node;
        var existing = target.Certificates.FirstOrDefault(c => CertificateUtil.NormalizeFingerprint(c.Sha256Fingerprint) == issued.Fingerprint);
        if (existing is not null)
        {
            log.LogInformation("[{Node}] ===== Step 6: The certificate from {Source} is already installed as '{Name}'", node, source, existing.FriendlyName);
            await ActivateAsync(target, issued, assignRoles: true, ct);
            return;
        }

        Step(node, "6", $"Importing the same certificate (exported from {source}) with its private key, with roles {IseRoles.Format(options.Roles)}");
        if (options.Roles.Contains(IseRole.Admin))
            log.LogWarning("[{Node}] Admin role change restarts the ISE application server on this node.", node);
        await ise.ImportSystemCertificateAsync(node,
            new SystemCertificateImport(issued.Installed.FriendlyName ?? $"LetsEncrypt {issued.Fingerprint[..12]}", exported, options.Roles, options.PortalGroupTag), ct);
        log.LogInformation("[{Node}] ===== Step 8: Roles {Roles} assigned by the import", node, IseRoles.Format(options.Roles));

        // Some ISE versions ignore the role flags on import if a role is held by a certificate with another subject.
        var installed = await FindByFingerprintAsync(node, issued.Fingerprint, ct)
                        ?? throw new InvalidOperationException($"Imported certificate {issued.Fingerprint} not found on {node}");
        await ActivateAsync(target, issued, assignRoles: options.Roles.Any(r => !installed.Roles.Contains(r)), ct);
    }

    private async Task HandleOldCertificatesAsync(NodeState state, string newId, CancellationToken ct)
    {
        var node = state.Node;
        var previous = state.PreviousHolderIds.Where(id => id != newId).ToList();
        if (previous.Count == 0)
        {
            log.LogInformation("[{Node}] No previous certificate held the roles.", node);
            return;
        }

        var current = await ise.GetSystemCertificatesAsync(node.Hostname, ct);
        foreach (var old in previous)
        {
            var now = current.FirstOrDefault(c => c.Id == old);
            if (now is null)
            {
                var name = state.Certificates.FirstOrDefault(c => c.Id == old)?.FriendlyName ?? old;
                log.LogInformation("[{Node}] The previous certificate '{Name}' has already been removed by ISE " +
                                   "(ISE replaces a certificate with the same subject when the roles move).", node, name);
                continue;
            }
            if (!now.IsUnused)
            {
                log.LogInformation("[{Node}] Keeping '{Name}' – still used by: {UsedBy}{Portals}", node, now.FriendlyName, now.UsedBy,
                    string.IsNullOrWhiteSpace(now.PortalsUsingTheTag) ? "" : $" (portals: {now.PortalsUsingTheTag})");
                continue;
            }
            if (options.KeepOldCertificates)
            {
                log.LogInformation("[{Node}] Keeping the no longer used certificate {Cert} (default; use -DeleteOldCertificates to delete it).", node, now);
                continue;
            }
            try
            {
                await ise.DeleteSystemCertificateAsync(node.Hostname, now.Id, ct);
                log.LogInformation("[{Node}] Deleted the no longer used certificate {Cert}", node, now);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                log.LogWarning("[{Node}] Could not delete {Cert}: {Error}", node, now, ex.Message);
            }
        }
    }

    /// <summary>Checks that ISE trusts every CA in the issued chain. Fails (before binding) and prints the missing ones.</summary>
    private async Task EnsureChainTrustedAsync(IseNode node, X509Certificate2 leaf, IReadOnlyList<X509Certificate2> issuers, CancellationToken ct)
    {
        var chain = await chainResolver.ResolveAsync(leaf, issuers, ct);
        var trusted = await ise.GetTrustedCertificatesAsync(ct);
        var missing = new List<X509Certificate2>();
        foreach (var ca in Enumerable.Reverse(chain))
        {
            var match = CaTrust.FindTrusted(ca, trusted);
            if (match is not null)
                log.LogInformation("[{Node}] CA '{Subject}' trusted by ISE as '{Name}' ✔", node, ca.Subject, match.FriendlyName);
            else
            {
                log.LogError("[{Node}] CA '{Subject}' in the issued chain is NOT trusted by ISE", node, ca.Subject);
                missing.Add(ca);
            }
        }
        if (missing.Count == 0)
            return;

        LogCertificatesToInstall(missing.Select(m => (CertificateUtil.CommonName(m), m,
            _requiredCas.FirstOrDefault(k => CertificateUtil.Sha256(k.Certificate) == CertificateUtil.Sha256(m))?.Url)));
        throw new InvalidOperationException(
            $"ISE does not trust {string.Join(", ", missing.Select(CertificateUtil.CommonName))} from the issued certificate chain. " +
            "The certificate was not installed. Install the CA certificate(s) in ISE (see the log above) and run again.");
    }

    private async Task VerifyServicesAsync(IseNode node, string fingerprint, CancellationToken ct)
    {
        if (options.SkipVerification)
        {
            log.LogWarning("[{Node}] Live verification skipped (-SkipVerification).", node);
            return;
        }

        foreach (var role in options.Roles.OrderBy(r => r))
        {
            switch (role)
            {
                case IseRole.Admin:
                    await WaitForCertificateAsync(node, "Admin (HTTPS 443)", fingerprint, required: true,
                        c => probe.GetTlsCertificateAsync(node.ProbeAddress, 443, null, c), ct);
                    break;
                case IseRole.Portal:
                    await WaitForCertificateAsync(node, $"Portal (HTTPS {options.PortalPort})", fingerprint, required: false,
                        c => probe.GetTlsCertificateAsync(node.ProbeAddress, options.PortalPort, options.CertificateDns[0], c), ct);
                    break;
                case IseRole.Eap when string.IsNullOrEmpty(options.RadiusSecret):
                    log.LogWarning("[{Node}] EAP: RADIUS verification skipped – no -RadiusSecret / RADIUS_SECRET given.", node);
                    break;
                case IseRole.Eap:
                    await WaitForCertificateAsync(node, $"EAP-PEAP (RADIUS {options.RadiusPort})", fingerprint, required: true,
                        c => probe.GetEapCertificateAsync(node.IpAddress ?? node.ProbeAddress, options.RadiusPort,
                            options.RadiusSecret!, options.RadiusIdentity, c), ct);
                    break;
                default:
                    log.LogInformation("[{Node}] {Role}: no live probe available – verified through the ISE API in step 10.", node, role);
                    break;
            }
        }
    }

    private async Task WaitForCertificateAsync(IseNode node, string service, string expected, bool required,
        Func<CancellationToken, Task<X509Certificate2>> fetch, CancellationToken ct)
    {
        var deadline = time.GetUtcNow() + options.VerifyTimeout;
        string? last = null;
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                var cert = await fetch(ct);
                last = CertificateUtil.Sha256(cert);
                if (last == expected)
                {
                    log.LogInformation("[{Node}] {Service}: presents the new certificate ({Subject}, sha256 {Fp}) ✔", node, service, cert.Subject, last);
                    return;
                }
                log.LogInformation("[{Node}] {Service}: still presents {Subject} (sha256 {Fp}) – waiting", node, service, cert.Subject, last);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                if (!required && attempt == 1)
                {
                    log.LogWarning("[{Node}] {Service}: not reachable ({Error}) – skipping live check.", node, service, ex.Message);
                    return;
                }
                log.LogInformation("[{Node}] {Service}: not reachable yet ({Error}) – waiting", node, service, ex.Message);
            }

            if (time.GetUtcNow() >= deadline)
                throw new InvalidOperationException(
                    $"{service} on {node} does not present the new certificate after {options.VerifyTimeout} (last seen sha256 {last ?? "none"}).");
            await Task.Delay(options.PollInterval, time, ct);
        }
    }

    private async Task VerifyInstallationAsync(IseNode node, string fingerprint, CancellationToken ct)
    {
        await WaitForApiAsync(ct);
        var certificates = await ise.GetSystemCertificatesAsync(node.Hostname, ct);
        var installed = certificates.FirstOrDefault(c => CertificateUtil.NormalizeFingerprint(c.Sha256Fingerprint) == fingerprint)
                        ?? throw new InvalidOperationException($"New certificate {fingerprint} is no longer present on {node}");

        var missing = options.Roles.Where(r => !installed.Roles.Contains(r)).ToList();
        if (missing.Count > 0)
            throw new InvalidOperationException($"New certificate on {node} is missing role(s) {IseRoles.Format(missing)} (usedBy: '{installed.UsedBy}')");

        var expires = installed.ExpiresUtc;
        if (expires is not null && expires <= time.GetUtcNow())
            throw new InvalidOperationException($"New certificate on {node} is expired ({installed.ExpirationDate})");

        foreach (var role in options.Roles.Intersect(ExclusiveRoles))
        {
            var others = certificates.Where(c => c.Id != installed.Id && c.Roles.Contains(role)).ToList();
            if (others.Count > 0)
                throw new InvalidOperationException($"Role {role} on {node} is still assigned to: {string.Join("; ", others)}");
        }
        log.LogInformation("[{Node}] ISE reports the new certificate {Cert} ✔", node, installed);
    }

    private async Task<SystemCertificate?> FindByFingerprintAsync(IseNode node, string fingerprint, CancellationToken ct)
    {
        var certificates = await ise.GetSystemCertificatesAsync(node.Hostname, ct);
        return certificates.FirstOrDefault(c => CertificateUtil.NormalizeFingerprint(c.Sha256Fingerprint) == fingerprint);
    }

    private async Task WaitForApiAsync(CancellationToken ct)
    {
        var deadline = time.GetUtcNow() + options.VerifyTimeout;
        while (!await ise.IsApiAvailableAsync(ct))
        {
            if (time.GetUtcNow() >= deadline)
                throw new InvalidOperationException($"ISE API on {options.AdmNode} did not come back within {options.VerifyTimeout}");
            log.LogInformation("Waiting for the ISE API on {AdmNode} (application server restarting?)", options.AdmNode);
            await Task.Delay(options.PollInterval, time, ct);
        }
    }

    private void Step(IseNode? node, string step, string text)
    {
        if (node is null)
            log.LogInformation("===== Step {Step}: {Text}", step, text);
        else
            log.LogInformation("[{Node}] ===== Step {Step}: {Text}", node, step, text);
    }
}
