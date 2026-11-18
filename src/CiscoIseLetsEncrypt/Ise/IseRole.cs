namespace CiscoIseLetsEncrypt.Ise;

/// <summary>Certificate usages ("roles") on a Cisco ISE system certificate.</summary>
public enum IseRole
{
    Admin,
    Eap,
    Dtls,
    Portal,
    PxGrid,
    Ims,
    Saml,
}

public static class IseRoles
{
    private static readonly Dictionary<string, IseRole> Aliases = new(StringComparer.OrdinalIgnoreCase)
    {
        ["ADMIN"] = IseRole.Admin,
        ["EAP"] = IseRole.Eap,
        ["EAP-AUTH"] = IseRole.Eap,
        ["EAP AUTHENTICATION"] = IseRole.Eap,
        ["DTLS"] = IseRole.Dtls,
        ["DTLS-AUTH"] = IseRole.Dtls,
        ["RADIUS"] = IseRole.Dtls,
        ["RADIUS DTLS"] = IseRole.Dtls,
        ["RADIUS-DTLS"] = IseRole.Dtls,
        ["RADSEC"] = IseRole.Dtls,
        ["PORTAL"] = IseRole.Portal,
        ["PXGRID"] = IseRole.PxGrid,
        ["IMS"] = IseRole.Ims,
        ["ISE MESSAGING SERVICE"] = IseRole.Ims,
        ["SAML"] = IseRole.Saml,
    };

    public static bool TryParse(string value, out IseRole role) => Aliases.TryGetValue(value.Trim(), out role);

    /// <summary>Parses the ISE "usedBy" string, e.g. "Admin, EAP Authentication, RADIUS DTLS".</summary>
    public static IReadOnlySet<IseRole> ParseUsedBy(string? usedBy)
    {
        var result = new HashSet<IseRole>();
        if (string.IsNullOrWhiteSpace(usedBy))
            return result;

        foreach (var part in usedBy.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (TryParse(part, out var role))
                result.Add(role);
        }
        return result;
    }

    /// <summary>
    /// The certificate usage to request in the CSR, or null for Multi-Use. EAP+DTLS uses the EAP type because ISE
    /// requires the node FQDN in the SAN of Multi-Use CSRs; all roles are assigned after bind anyway.
    /// </summary>
    public static IseRole? CsrUsage(IReadOnlyCollection<IseRole> roles) =>
        roles.Count == 1 ? roles.First()
        : roles.Count > 0 && roles.All(r => r is IseRole.Eap or IseRole.Dtls) ? IseRole.Eap
        : null;

    /// <summary>Value for the "usedFor" field when generating a CSR with the ISE OpenAPI.</summary>
    public static string ToCsrUsedFor(IReadOnlyCollection<IseRole> roles) => CsrUsage(roles) switch
    {
        IseRole.Admin => "ADMIN",
        IseRole.Eap => "EAP-AUTH",
        IseRole.Dtls => "DTLS-AUTH",
        IseRole.Portal => "PORTAL",
        IseRole.PxGrid => "PXGRID",
        IseRole.Ims => "IMS",
        IseRole.Saml => "SAML",
        _ => "MULTI-USE",
    };

    public static string Format(IEnumerable<IseRole> roles) => string.Join(",", roles.OrderBy(r => r));
}
