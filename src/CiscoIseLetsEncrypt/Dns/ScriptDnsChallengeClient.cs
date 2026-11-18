using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace CiscoIseLetsEncrypt.Dns;

/// <summary>
/// DNS provider hook for providers other than the ACME DNS Proxy. Runs a PowerShell script:
/// <c>pwsh -NoProfile -NonInteractive -File script.ps1 -Action Create -RecordName _acme-challenge.x -Value txt</c>
/// and <c>-Action Delete -RecordName _acme-challenge.x</c>. Exit code 0 = success; anything else fails the run
/// (stderr/stdout is included in the error).
/// </summary>
public sealed class ScriptDnsChallengeClient : IDnsChallengeClient
{
    private readonly string scriptPath;
    private readonly string executable;
    private readonly string[] leadingArguments;
    private readonly TimeSpan timeout;
    private readonly ILogger<ScriptDnsChallengeClient> log;

    public ScriptDnsChallengeClient(string scriptPath, TimeSpan timeout, ILogger<ScriptDnsChallengeClient> log,
        string? executable = null, string[]? leadingArguments = null)
    {
        this.scriptPath = scriptPath;
        this.timeout = timeout;
        this.log = log;
        this.executable = executable ?? DefaultPowerShell();
        this.leadingArguments = leadingArguments ?? ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"];
    }

    public Task CreateTxtRecordAsync(string recordName, string value, CancellationToken ct) =>
        RunAsync("Create", recordName, value, ct);

    public Task DeleteTxtRecordAsync(string recordName, CancellationToken ct) =>
        RunAsync("Delete", recordName, null, ct);

    private static string DefaultPowerShell() => OperatingSystem.IsWindows() ? "powershell.exe" : "pwsh";

    private async Task RunAsync(string action, string recordName, string? value, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(executable)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var a in leadingArguments) psi.ArgumentList.Add(a);
        psi.ArgumentList.Add(scriptPath);
        psi.ArgumentList.Add("-Action");
        psi.ArgumentList.Add(action);
        psi.ArgumentList.Add("-RecordName");
        psi.ArgumentList.Add(recordName);
        if (value is not null)
        {
            psi.ArgumentList.Add("-Value");
            psi.ArgumentList.Add(value);
        }

        log.LogDebug("DNS script {Executable} {Args}", executable, string.Join(' ', psi.ArgumentList));
        Process process;
        try
        {
            process = Process.Start(psi) ?? throw new DnsProxyException($"DNS script could not be started ({executable}).");
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            throw new DnsProxyException($"DNS script could not be started ({executable}): {ex.Message}");
        }

        using (process)
        {
            process.StandardInput.Close();
            var stdout = process.StandardOutput.ReadToEndAsync(CancellationToken.None);
            var stderr = process.StandardError.ReadToEndAsync(CancellationToken.None);
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(timeout);
            try
            {
                await process.WaitForExitAsync(timeoutCts.Token);
            }
            catch (OperationCanceledException)
            {
                try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
                if (ct.IsCancellationRequested) throw;
                throw new DnsProxyException($"DNS script {action} for {recordName} timed out after {timeout.TotalSeconds:0}s.");
            }

            var output = (await stdout + Environment.NewLine + await stderr).Trim();
            if (process.ExitCode != 0)
                throw new DnsProxyException($"DNS script {action} for {recordName} failed (exit code {process.ExitCode}): {output}");
            if (output.Length > 0)
                log.LogDebug("DNS script output: {Output}", output);
        }
        log.LogInformation("DNS script: {Action} ok for {Record}", action, recordName);
    }
}
