using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CiscoIseLetsEncrypt.Certificates;

public sealed record CsrDetails(string CommonName, IReadOnlyList<string> DnsNames, byte[] Der)
{
    /// <summary>All DNS identifiers (CN + SANs) that must be in the ACME order.</summary>
    public IReadOnlyList<string> AllNames =>
        DnsNames.Prepend(CommonName).Where(n => !string.IsNullOrEmpty(n))
            .Select(n => n.ToLowerInvariant()).Distinct().ToList();
}

/// <summary>CSR made by this program with a key that only exists in memory, plus the key encrypted for import into ISE.</summary>
public sealed record LocalKeyCsr(CsrDetails Csr, string EncryptedPrivateKeyPem, string Password);

public static class CertificateUtil
{
    /// <summary>
    /// Generates a key pair and CSR locally (fallback when ISE refuses to make the CSR). The private key is only
    /// returned PKCS#8-encrypted with a random password and is never written to disk.
    /// </summary>
    public static LocalKeyCsr CreateLocalKeyCsr(IReadOnlyList<string> names, string keyType, string keyLength, string digestType)
    {
        var hash = digestType.Replace("-", "").ToUpperInvariant() switch
        {
            "SHA384" => HashAlgorithmName.SHA384,
            "SHA512" => HashAlgorithmName.SHA512,
            _ => HashAlgorithmName.SHA256,
        };
        var subject = new X500DistinguishedName($"CN={names[0]}");
        using AsymmetricAlgorithm key = keyType == "ECDSA"
            ? ECDsa.Create(keyLength switch { "384" => ECCurve.NamedCurves.nistP384, "521" => ECCurve.NamedCurves.nistP521, _ => ECCurve.NamedCurves.nistP256 })
            : RSA.Create(Math.Max(2048, int.TryParse(keyLength, out var bits) ? bits : 2048));
        var req = key is RSA rsa
            ? new CertificateRequest(subject, rsa, hash, RSASignaturePadding.Pkcs1)
            : new CertificateRequest(subject, (ECDsa)key, hash);
        var san = new SubjectAlternativeNameBuilder();
        foreach (var n in names)
            san.AddDnsName(n);
        req.CertificateExtensions.Add(san.Build());
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | (key is RSA ? X509KeyUsageFlags.KeyEncipherment : 0), true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            [new Oid("1.3.6.1.5.5.7.3.1"), new Oid("1.3.6.1.5.5.7.3.2")], false));

        // Alphanumeric, as required by ISE. Only kept in memory for the duration of the run.
        var password = RandomNumberGenerator.GetString("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789", 40);
        var keyPem = new string(key.ExportEncryptedPkcs8PrivateKeyPem(password,
            new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000)));
        return new LocalKeyCsr(ParseCsr(req.CreateSigningRequestPem()), keyPem, password);
    }

    public static CsrDetails ParseCsr(string pem)
    {
        var req = CertificateRequest.LoadSigningRequestPem(pem, HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
        var cn = req.SubjectName.EnumerateRelativeDistinguishedNames()
            .Where(r => r.GetSingleElementType().Value == "2.5.4.3")
            .Select(r => r.GetSingleElementValue() ?? "")
            .FirstOrDefault() ?? "";

        var dns = req.CertificateExtensions.OfType<X509SubjectAlternativeNameExtension>()
            .SelectMany(e => e.EnumerateDnsNames()).ToList();
        if (dns.Count == 0)
        {
            foreach (var ext in req.CertificateExtensions.Where(e => e.Oid?.Value == "2.5.29.17"))
                dns.AddRange(new X509SubjectAlternativeNameExtension(ext.RawData, ext.Critical).EnumerateDnsNames());
        }

        var der = PemToDer(pem, "CERTIFICATE REQUEST");
        return new CsrDetails(cn, dns, der);
    }

    public static byte[] PemToDer(string pem, string label)
    {
        var fields = PemEncoding.Find(pem);
        var found = pem[fields.Label];
        if (!string.Equals(found, label, StringComparison.Ordinal) &&
            !string.Equals(found, "NEW " + label, StringComparison.Ordinal))
            throw new CryptographicException($"Expected PEM '{label}' but found '{found}'.");
        return Convert.FromBase64String(pem[fields.Base64Data]);
    }

    public static string ToPem(X509Certificate2 cert) => cert.ExportCertificatePem() + "\n";

    public static string Sha256(X509Certificate2 cert) => Convert.ToHexStringLower(cert.GetCertHash(HashAlgorithmName.SHA256));

    /// <summary>Normalizes fingerprints like "AA:BB:.." / "aabb.." for comparison.</summary>
    public static string NormalizeFingerprint(string? fp) =>
        new string((fp ?? "").Where(Uri.IsHexDigit).ToArray()).ToLowerInvariant();

    public static bool IsSelfSigned(X509Certificate2 cert) =>
        cert.SubjectName.RawData.AsSpan().SequenceEqual(cert.IssuerName.RawData);

    public static string CommonName(X509Certificate2 cert) => cert.GetNameInfo(X509NameType.SimpleName, false);

    public static IReadOnlyList<string> DnsNames(X509Certificate2 cert) =>
        cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().SelectMany(e => e.EnumerateDnsNames()).ToList();

    /// <summary>Reads certificates from DER or PEM (one or more) bytes.</summary>
    public static IReadOnlyList<X509Certificate2> LoadCertificates(byte[] data)
    {
        var text = System.Text.Encoding.ASCII.GetString(data);
        if (text.Contains("-----BEGIN CERTIFICATE-----"))
        {
            var col = new X509Certificate2Collection();
            col.ImportFromPem(text);
            return col.Cast<X509Certificate2>().ToList();
        }
        return [X509CertificateLoader.LoadCertificate(data)];
    }
}
