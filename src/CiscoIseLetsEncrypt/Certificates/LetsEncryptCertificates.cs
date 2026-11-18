using System.Security.Cryptography.X509Certificates;
using CiscoIseLetsEncrypt.Ise;

namespace CiscoIseLetsEncrypt.Certificates;

public enum AcmeEnvironment { Production, Staging }

public enum CaKeyType { RSA, ECDSA }

/// <summary>Root and Intermediate must be trusted by ISE; Backup intermediates only give a warning.</summary>
public enum CaKind { Root, Intermediate, Backup }

/// <summary>
/// A Let's Encrypt CA certificate. Certificates with the same <see cref="Group"/> are variants of the same CA
/// (self-signed and cross-signed: same subject and key) – trusting one of them is enough.
/// </summary>
public sealed record KnownCa(AcmeEnvironment Environment, CaKeyType KeyType, CaKind Kind, string Group, string Label, string Url, string Base64Der)
{
    private X509Certificate2? _certificate;

    public X509Certificate2 Certificate => _certificate ??= X509CertificateLoader.LoadCertificate(Convert.FromBase64String(Base64Der));
}

public static partial class LetsEncryptCertificates
{
    /// <summary>The Let's Encrypt CAs ISE must trust before certificates for <paramref name="keyType"/> can be installed.</summary>
    public static IReadOnlyList<KnownCa> For(bool staging, string keyType)
    {
        var env = staging ? AcmeEnvironment.Staging : AcmeEnvironment.Production;
        return All.Where(c => c.Environment == env && c.KeyType.ToString().Equals(keyType, StringComparison.OrdinalIgnoreCase)).ToList();
    }
}

public static class CaTrust
{
    /// <summary>
    /// Finds the trusted certificate in ISE for <paramref name="ca"/>: same fingerprint, or same subject (a cross-signed or
    /// self-signed variant of the same CA). Returns null when ISE does not trust it.
    /// </summary>
    public static TrustedCertificate? FindTrusted(X509Certificate2 ca, IReadOnlyList<TrustedCertificate> trusted)
    {
        var fp = CertificateUtil.Sha256(ca);
        return trusted.FirstOrDefault(t => CertificateUtil.NormalizeFingerprint(t.Sha256Fingerprint) == fp)
               ?? trusted.FirstOrDefault(t => SameSubject(t.Subject, ca.SubjectName.Name));
    }

    public static bool SameSubject(string? a, string? b) =>
        !string.IsNullOrWhiteSpace(a) && !string.IsNullOrWhiteSpace(b) && Rdns(a).SetEquals(Rdns(b));

    private static HashSet<string> Rdns(string subject) =>
        subject.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(p => p.Split('=', 2))
            .Where(p => p.Length == 2)
            .Select(p => $"{p[0].Trim().ToUpperInvariant()}={p[1].Trim().Trim('"').ToLowerInvariant()}")
            .ToHashSet();
}
