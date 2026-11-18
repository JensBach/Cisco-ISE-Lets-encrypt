namespace CiscoIseLetsEncrypt.Acme;

public sealed record DnsChallenge(string Domain, string RecordName, string TxtValue);

public sealed record IssuedCertificate(string LeafPem, IReadOnlyList<string> IssuerPems);

public interface IAcmeService
{
    string ServerDescription { get; }
    Task<IAcmeOrder> NewOrderAsync(IReadOnlyList<string> dnsNames, CancellationToken ct);
}

public interface IAcmeOrder
{
    /// <summary>DNS-01 challenges for authorizations that are not already valid.</summary>
    Task<IReadOnlyList<DnsChallenge>> GetPendingDnsChallengesAsync(CancellationToken ct);

    /// <summary>Asks the CA to validate the challenges and waits for all authorizations to become valid.</summary>
    Task ValidateAsync(CancellationToken ct);

    /// <summary>Finalizes the order with an externally generated CSR (DER) and downloads the certificate.</summary>
    Task<IssuedCertificate> FinalizeAsync(byte[] csrDer, CancellationToken ct);
}

public sealed class AcmeException(string message) : Exception(message);
