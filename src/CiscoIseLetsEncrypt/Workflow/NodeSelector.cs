using CiscoIseLetsEncrypt.Ise;

namespace CiscoIseLetsEncrypt.Workflow;

public static class NodeSelector
{
    /// <summary>
    /// Step 2: selects nodes to update. Explicit -Node values must exist in the deployment; otherwise nodes
    /// are picked by persona/services needed for the roles. The admin node is processed last because an Admin
    /// role change restarts its application server (and the API).
    /// </summary>
    public static IReadOnlyList<IseNode> Select(IReadOnlyList<IseNode> deployment, IReadOnlyCollection<string> requested,
        IReadOnlyCollection<IseRole> roles, string adminNode)
    {
        List<IseNode> selected;
        if (requested.Count > 0)
        {
            selected = [];
            foreach (var name in requested)
            {
                var node = deployment.FirstOrDefault(n => n.Matches(name))
                           ?? throw new InvalidOperationException(
                               $"Node '{name}' is not part of the ISE deployment ({string.Join(", ", deployment)}).");
                if (!selected.Contains(node))
                    selected.Add(node);
            }
        }
        else
        {
            selected = deployment.Where(n => IsRelevant(n, roles)).ToList();
        }

        return selected.OrderBy(n => n.Matches(adminNode) || n.Matches(adminNode.Split('.')[0]) ? 1 : 0).ToList();
    }

    public static bool IsRelevant(IseNode node, IReadOnlyCollection<IseRole> roles) =>
        roles.Any(role => role switch
        {
            IseRole.Eap or IseRole.Dtls or IseRole.Portal => HasService(node, "Session"),
            IseRole.PxGrid => HasService(node, "pxGrid"),
            _ => true,
        });

    private static bool HasService(IseNode node, string service) =>
        node.Services.Any(s => s.Equals(service, StringComparison.OrdinalIgnoreCase));
}
