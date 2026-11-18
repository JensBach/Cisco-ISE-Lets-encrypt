using CiscoIseLetsEncrypt.Ise;

namespace CiscoIseLetsEncrypt.Workflow;

public sealed record RenewalDecision(bool Renew, IReadOnlyList<string> Reasons);

public static class RenewalPolicy
{
    /// <summary>Step 2a/2b: decides whether the certificates currently holding the roles must be replaced.</summary>
    public static RenewalDecision Evaluate(IReadOnlyList<SystemCertificate> certificates, IReadOnlyCollection<IseRole> roles,
        IReadOnlyCollection<string> expectedDnsNames, int renewBeforeDays, bool acmeTest, DateTimeOffset now)
    {
        var reasons = new List<string>();
        foreach (var role in roles.OrderBy(r => r))
        {
            var holders = certificates.Where(c => c.Roles.Contains(role)).ToList();
            if (holders.Count == 0)
            {
                reasons.Add($"{role}: no certificate is assigned this role");
                continue;
            }

            foreach (var cert in holders)
            {
                if (!expectedDnsNames.Contains(cert.IssuedTo ?? "", StringComparer.OrdinalIgnoreCase))
                    reasons.Add($"{role}: certificate '{cert.FriendlyName}' is issued to '{cert.IssuedTo}', expected {string.Join("/", expectedDnsNames)}");

                if (cert.SelfSigned == true)
                    reasons.Add($"{role}: certificate '{cert.FriendlyName}' is self-signed");

                var expires = cert.ExpiresUtc;
                if (expires is null)
                    reasons.Add($"{role}: cannot parse expiration date '{cert.ExpirationDate}'");
                else if (expires.Value - now < TimeSpan.FromDays(renewBeforeDays))
                    reasons.Add($"{role}: certificate '{cert.FriendlyName}' expires {expires:yyyy-MM-dd} (within {renewBeforeDays} days)");

                var isStaging = (cert.IssuedBy ?? "").Contains("STAGING", StringComparison.OrdinalIgnoreCase);
                if (!acmeTest && isStaging)
                    reasons.Add($"{role}: certificate '{cert.FriendlyName}' is a Let's Encrypt STAGING certificate");
            }
        }
        return new RenewalDecision(reasons.Count > 0, reasons.Distinct().ToList());
    }
}
