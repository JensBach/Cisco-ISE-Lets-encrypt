using System.Net;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using CiscoIseLetsEncrypt.Acme;
using CiscoIseLetsEncrypt.Certificates;
using CiscoIseLetsEncrypt.Cli;
using CiscoIseLetsEncrypt.Dns;
using CiscoIseLetsEncrypt.Ise;
using CiscoIseLetsEncrypt.Verification;
using CiscoIseLetsEncrypt.Workflow;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.UserSecrets;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Events;

if (ArgumentParser.IsHelp(args))
{
    Console.WriteLine(ArgumentParser.HelpText);
    return 0;
}

if (args.Length > 0 && args[0].TrimStart('-', '/').Equals("SetSecret", StringComparison.OrdinalIgnoreCase))
    return SetSecret(args.Skip(1).FirstOrDefault());

var secrets = new ConfigurationBuilder().AddUserSecrets(typeof(Program).Assembly, optional: true).Build();

AppOptions options;
try
{
    options = ArgumentParser.Parse(args, Environment.GetEnvironmentVariable, k => secrets[k] is { Length: > 0 } v ? v : null);
}
catch (CliArgumentException ex)
{
    Console.Error.WriteLine($"Error: {ex.Message}");
    Console.Error.WriteLine("Run with -Help for usage.");
    return 2;
}

Directory.CreateDirectory(options.LogDirectory);
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Is(options.Verbose ? LogEventLevel.Debug : LogEventLevel.Information)
    .MinimumLevel.Override("System.Net.Http", LogEventLevel.Warning)
    .WriteTo.Console(outputTemplate: "{Timestamp:HH:mm:ss} [{Level:u3}] {Message:lj}{NewLine}{Exception}")
    .WriteTo.File(Path.Combine(options.LogDirectory, "CiscoIseLetsEncrypt-.log"), rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 90,
        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}")
    .CreateLogger();

using var loggerFactory = LoggerFactory.Create(b => b.AddSerilog(dispose: false));
var log = loggerFactory.CreateLogger("CiscoIseLetsEncrypt");
using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

try
{
    if (options.Backup)
    {
        log.LogInformation("CiscoIseLetsEncrypt backup started: AdmNode={AdmNode}", options.AdmNode);
        using var backupHttp = IseClient.CreateHttpClient(options.AdmNode, options.IseUsername, options.IsePassword, options.SkipIseTlsValidation);
        var backup = await new CertificateBackup(new IseClient(backupHttp, loggerFactory.CreateLogger<IseClient>()), TimeProvider.System,
            loggerFactory.CreateLogger<CertificateBackup>()).RunAsync(options.BackupDirectory, options.BackupPassword, cts.Token);
        return backup.Failed > 0 ? 1 : 0;
    }

    log.LogInformation("CiscoIseLetsEncrypt started: AdmNode={AdmNode} Nodes={Nodes} Roles={Roles} CertificateDNS={Dns} AcmeTest={Test} Force={Force}",
        options.AdmNode, options.Nodes.Count > 0 ? string.Join(",", options.Nodes) : "(auto)", IseRoles.Format(options.Roles),
        string.Join(",", options.CertificateDns), options.AcmeTest, options.Force);
    log.LogInformation("DryRun={DryRun} KeepOldCertificates={Keep}", options.DryRun, options.KeepOldCertificates);

    using var iseHttp = IseClient.CreateHttpClient(options.AdmNode, options.IseUsername, options.IsePassword, options.SkipIseTlsValidation);
    using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(1) };

    var workflow = new RenewalWorkflow(
        options,
        new IseClient(iseHttp, loggerFactory.CreateLogger<IseClient>(),
            host => IseClient.CreateHttpClient(host, options.IseUsername, options.IsePassword, options.SkipIseTlsValidation)),
        new CertesAcmeService(options.AcmeTest, options.ResolveAcmeAccountKeyPath(), options.AcmeEmail,
            TimeSpan.FromSeconds(3), TimeSpan.FromMinutes(5), loggerFactory.CreateLogger<CertesAcmeService>()),
        options.DnsScript is not null
            ? new ScriptDnsChallengeClient(options.DnsScript, options.DnsScriptTimeout,
                loggerFactory.CreateLogger<ScriptDnsChallengeClient>())
            : new AcmeDnsProxyClient(http, options.DnsChallengeUrl!, options.DnsChallengeToken,
                loggerFactory.CreateLogger<AcmeDnsProxyClient>()),
        new DnsPropagationChecker(options.DnsResolvers.Select(IPAddress.Parse).ToList(), options.PollInterval,
            loggerFactory.CreateLogger<DnsPropagationChecker>()),
        new IssuerChainResolver(http, loggerFactory.CreateLogger<IssuerChainResolver>()),
        new CertificateProbe(TimeSpan.FromSeconds(30)),
        TimeProvider.System,
        loggerFactory.CreateLogger<RenewalWorkflow>());

    var results = await workflow.RunAsync(cts.Token);
    return results.Any(r => r.Outcome == NodeOutcome.Failed) ? 1 : 0;
}
catch (Exception ex)
{
    log.LogCritical(ex, "Fatal error: {Error}", ex.Message);
    if (ex is HttpRequestException { InnerException: System.Security.Authentication.AuthenticationException })
        log.LogCritical("The ISE admin certificate is not trusted by this host. Trust the issuing CA, or use -SkipIseTlsValidation.");
    return 1;
}
finally
{
    await Log.CloseAndFlushAsync();
}

static int SetSecret(string? key)
{
    var known = ArgumentParser.SecretKeys.All.FirstOrDefault(k => k.Equals(key, StringComparison.OrdinalIgnoreCase));
    if (known is null)
    {
        Console.Error.WriteLine($"Usage: CiscoIseLetsEncrypt -SetSecret <{string.Join("|", ArgumentParser.SecretKeys.All)}>");
        return 2;
    }

    string? value;
    if (Console.IsInputRedirected)
        value = Console.In.ReadLine();
    else
    {
        Console.Write($"Value for {known}: ");
        var sb = new System.Text.StringBuilder();
        for (var k = Console.ReadKey(true); k.Key != ConsoleKey.Enter; k = Console.ReadKey(true))
        {
            if (k.Key == ConsoleKey.Backspace) { if (sb.Length > 0) sb.Length--; }
            else if (!char.IsControl(k.KeyChar)) sb.Append(k.KeyChar);
        }
        Console.WriteLine();
        value = sb.ToString();
    }
    if (string.IsNullOrEmpty(value?.Trim()))
    {
        Console.Error.WriteLine("Empty value – nothing stored.");
        return 2;
    }

    var id = typeof(Program).Assembly.GetCustomAttribute<UserSecretsIdAttribute>()!.UserSecretsId;
    var path = PathHelper.GetSecretsPathFromSecretsId(id);
    Directory.CreateDirectory(Path.GetDirectoryName(path)!);
    var json = File.Exists(path) ? JsonNode.Parse(File.ReadAllText(path)) as JsonObject ?? [] : [];
    json[known] = value.Trim();
    File.WriteAllText(path, json.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
    if (!OperatingSystem.IsWindows())
        File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    Console.WriteLine($"Stored {known} in {path}");
    return 0;
}
