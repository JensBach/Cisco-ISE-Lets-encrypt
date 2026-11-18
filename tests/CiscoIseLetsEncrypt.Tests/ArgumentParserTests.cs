using CiscoIseLetsEncrypt.Cli;
using CiscoIseLetsEncrypt.Ise;

namespace CiscoIseLetsEncrypt.Tests;

public class ArgumentParserTests
{
    private static readonly Dictionary<string, string> Env = new()
    {
        ["ISE_USERNAME"] = "user", ["ISE_PASSWORD"] = "pw", ["ACMEDNSPROXY_TOKEN"] = "tok", ["RADIUS_SECRET"] = "rad",
    };

    private static AppOptions Parse(params string[] args) => ArgumentParser.Parse(args, k => Env.GetValueOrDefault(k));

    private static readonly string[] Example =
    [
        "-AdmNode", "ise-pan.example.com", "-Node", "ise-17-a.example.com", "-roles", "EAP,DTLS",
        "-CertificateDNS", "eap.example.com", "-DnsChallengeUrl", "https://dns/api/txt",
    ];

    [Fact]
    public void Parses_the_documented_command_line()
    {
        var o = Parse(Example);

        Assert.Equal("ise-pan.example.com", o.AdmNode);
        Assert.Equal(["ise-17-a.example.com"], o.Nodes);
        Assert.Equal([IseRole.Eap, IseRole.Dtls], o.Roles);
        Assert.Equal(["eap.example.com"], o.CertificateDns);
        Assert.Equal(new Uri("https://dns/api/txt"), o.DnsChallengeUrl);
        Assert.Equal(("user", "pw", "tok"), (o.IseUsername, o.IsePassword, o.DnsChallengeToken));
        Assert.False(o.AcmeTest);
        Assert.False(o.Force);
    }

    [Fact]
    public void Parses_switches_case_insensitively()
    {
        var o = Parse([.. Example, "--acmetest", "/FORCE", "-RenewBeforeDays", "10"]);

        Assert.True(o.AcmeTest);
        Assert.True(o.Force);
        Assert.Equal(10, o.RenewBeforeDays);
        Assert.EndsWith("acme-account-staging.pem", o.ResolveAcmeAccountKeyPath());
    }

    [Fact]
    public void Dns_base_url_gets_api_path_and_admnode_url_is_stripped()
    {
        var o = Parse("-AdmNode", "https://ise-17-a.example.com/", "-Roles", "Admin", "-CertificateDNS", "a.example.com",
            "-DnsChallengeUrl", "https://dns");

        Assert.Equal("ise-17-a.example.com", o.AdmNode);
        Assert.Equal(new Uri("https://dns/api/txt"), o.DnsChallengeUrl);
    }

    [Fact]
    public void Old_create_and_delete_url_options_are_accepted_when_equal()
    {
        var o = Parse("-AdmNode", "a", "-Roles", "Admin", "-CertificateDNS", "a.example.com",
            "-DnsChallengeCreateURL", "https://dns/api/txt", "-DnsChallengeDeleteURL", "https://dns/api/txt");
        Assert.Equal(new Uri("https://dns/api/txt"), o.DnsChallengeUrl);

        var ex = Assert.Throws<CliArgumentException>(() => Parse("-AdmNode", "a", "-Roles", "Admin", "-CertificateDNS", "a.example.com",
            "-DnsChallengeCreateURL", "https://dns/api/txt", "-DnsChallengeDeleteURL", "https://other/api/txt"));
        Assert.Contains("Only one", ex.Message);
    }

    [Fact]
    public void Reads_secrets_from_key_value_files()
    {
        var cred = Path.GetTempFileName();
        var tok = Path.GetTempFileName();
        File.WriteAllText(cred, "url : https://ise\nusername: copilot\npassword: p:a:ss\n");
        File.WriteAllText(tok, "DNShost : dns\ntoken   : abc123\ndns name : eap.example.com\n");
        try
        {
            var o = ArgumentParser.Parse([.. Example, "-IseCredentialFile", cred, "-DnsTokenFile", tok, "-RadiusSecret", "r"], _ => null);

            Assert.Equal(("copilot", "p:a:ss", "abc123"), (o.IseUsername, o.IsePassword, o.DnsChallengeToken));
        }
        finally
        {
            File.Delete(cred);
            File.Delete(tok);
        }
    }

    [Fact]
    public void DnsScript_replaces_the_proxy_options()
    {
        var script = Path.GetTempFileName();
        try
        {
            var args = Example.Where((_, i) => i < Example.Length - 2).Concat(["-DnsScript", script, "-DnsScriptTimeoutSeconds", "30"]).ToArray();
            var o = ArgumentParser.Parse(args, k => k == "ISE_USERNAME" ? "u" : k == "ISE_PASSWORD" ? "p" : k == "RADIUS_SECRET" ? "r" : null);

            Assert.Equal(Path.GetFullPath(script), o.DnsScript);
            Assert.Null(o.DnsChallengeUrl);
            Assert.Equal(TimeSpan.FromSeconds(30), o.DnsScriptTimeout);
            Assert.Throws<CliArgumentException>(() => Parse([.. Example, "-DnsScript", script]));
            Assert.Throws<CliArgumentException>(() => Parse([.. Example.Take(Example.Length - 2), "-DnsScript", script + ".missing"]));
        }
        finally { File.Delete(script); }
    }

    [Fact]
    public void DnsScript_cannot_be_combined_with_proxy_url()
    {
        var script = Path.GetTempFileName();
        try
        {
            var ex = Assert.Throws<CliArgumentException>(() => Parse([.. Example, "-DnsScript", script]));
            Assert.Contains("cannot be combined", ex.Message);
        }
        finally { File.Delete(script); }
    }

    [Theory]
    [InlineData("-RenewBeforeDays", "-1")]
    [InlineData("-RenewBeforeDays", "abc")]
    [InlineData("-RadiusPort", "70000")]
    [InlineData("-PortalPort", "0")]
    [InlineData("-KeyType", "DSA")]
    [InlineData("-DnsResolvers", "not-an-ip")]
    [InlineData("-DnsPropagationTimeoutSeconds", "99999")]
    public void Rejects_out_of_range_values(string name, string value) =>
        Assert.Throws<CliArgumentException>(() => Parse([.. Example, name, value]));

    [Fact]
    public void Missing_value_and_unexpected_argument_are_rejected()
    {
        Assert.Contains("Missing value", Assert.Throws<CliArgumentException>(() => Parse([.. Example, "-AcmeEmail"])).Message);
        Assert.Contains("Unexpected", Assert.Throws<CliArgumentException>(() => Parse([.. Example, "stray"])).Message);
    }

    [Fact]
    public void Delete_and_keep_old_certificates_conflict_and_delete_turns_keep_off()
    {
        Assert.True(Parse(Example).KeepOldCertificates);
        Assert.False(Parse([.. Example, "-DeleteOldCertificates"]).KeepOldCertificates);
        Assert.Throws<CliArgumentException>(() => Parse([.. Example, "-DeleteOldCertificates", "-KeepOldCertificates"]));
    }

    [Fact]
    public void Eap_requires_radius_secret_unless_verification_is_skipped()
    {
        string? NoRadius(string k) => k == "RADIUS_SECRET" ? null : "x";
        Assert.Throws<CliArgumentException>(() => ArgumentParser.Parse(Example, NoRadius));
        Assert.True(ArgumentParser.Parse([.. Example, "-SkipVerification"], NoRadius).SkipVerification);
    }

    [Fact]
    public void Backup_mode_needs_only_ise_options_and_a_long_password()
    {
        var o = Parse("-AdmNode", "pan", "-Backup", "-BackupPassword", "longenough", "-BackupDirectory", "bk");
        Assert.True(o.Backup);
        Assert.Equal("bk", o.BackupDirectory);

        Assert.Throws<CliArgumentException>(() => Parse("-AdmNode", "pan", "-Backup", "-BackupPassword", "short"));
    }

    [Fact]
    public void Switch_accepts_explicit_boolean_and_inline_values()
    {
        Assert.False(Parse([.. Example, "-Force:false"]).Force);
        Assert.True(Parse([.. Example, "-Force:true"]).Force);
        Assert.Equal(7, Parse([.. Example, "-RenewBeforeDays=7"]).RenewBeforeDays);
        Assert.True(Parse([.. Example, "-WhatIf"]).DryRun);
    }

    [Fact]
    public void Certificate_names_are_lowercased_and_deduplicated_and_lists_split()
    {
        var o = Parse("-AdmNode", "a", "-Roles", "Admin,admin", "-CertificateDNS", "A.example.com,a.example.com b.example.com",
            "-DnsChallengeUrl", "https://dns", "-DnsResolvers", "9.9.9.9;1.1.1.1");

        Assert.Equal(["a.example.com", "b.example.com"], o.CertificateDns);
        Assert.Equal([IseRole.Admin], o.Roles);
        Assert.Equal(["9.9.9.9", "1.1.1.1"], o.DnsResolvers);
    }

    [Theory]
    [InlineData(new string[0], true)]
    [InlineData(new[] { "-help" }, true)]
    [InlineData(new[] { "/?" }, true)]
    [InlineData(new[] { "-AdmNode", "x" }, false)]
    public void IsHelp_detects_help_requests(string[] args, bool expected) =>
        Assert.Equal(expected, ArgumentParser.IsHelp(args));

    [Fact]
    public void ReadKeyValueFile_throws_for_missing_file() =>
        Assert.Throws<CliArgumentException>(() => ArgumentParser.ReadKeyValueFile("/nonexistent/file.txt"));

    [Theory]
    [InlineData("-Roles", "EAP,Foo", "Unknown role")]
    [InlineData("-Roles", "SAML,EAP", "SAML cannot be combined")]
    [InlineData("-CertificateDNS", "*.example.com", "Wildcard")]
    [InlineData("-DnsChallengeUrl", "not-a-url", "absolute")]
    [InlineData("-Bogus", "x", "Unknown option")]
    public void Rejects_invalid_arguments(string name, string value, string message)
    {
        var args = Example.ToList();
        var idx = args.FindIndex(a => a.Equals(name, StringComparison.OrdinalIgnoreCase));
        if (idx >= 0) args[idx + 1] = value;
        else args.AddRange([name, value]);

        var ex = Assert.Throws<CliArgumentException>(() => Parse([.. args]));
        Assert.Contains(message, ex.Message);
    }

    [Fact]
    public void Missing_token_is_reported()
    {
        var ex = Assert.Throws<CliArgumentException>(() => ArgumentParser.Parse(Example, k => k == "ACMEDNSPROXY_TOKEN" ? null : "x"));
        Assert.Contains("token", ex.Message);
    }

    [Fact]
    public void User_secrets_are_used_after_command_line_files_and_environment()
    {
        var secrets = new Dictionary<string, string>
        {
            [ArgumentParser.SecretKeys.IseUsername] = "su", [ArgumentParser.SecretKeys.IsePassword] = "sp",
            [ArgumentParser.SecretKeys.DnsToken] = "st", [ArgumentParser.SecretKeys.RadiusSecret] = "sr",
        };
        var env = new Dictionary<string, string> { ["ISE_PASSWORD"] = "ep" };

        var o = ArgumentParser.Parse([.. Example, "-DnsChallengeToken", "cli"], k => env.GetValueOrDefault(k), k => secrets.GetValueOrDefault(k));

        Assert.Equal(("su", "ep", "cli", "sr"), (o.IseUsername, o.IsePassword, o.DnsChallengeToken, o.RadiusSecret));
    }

    [Fact]
    public void Eap_without_radius_secret_is_rejected_unless_verification_is_skipped()
    {
        Env.Remove("RADIUS_SECRET", out var saved);
        try
        {
            Assert.Throws<CliArgumentException>(() => Parse(Example));
            Assert.Null(Parse([.. Example, "-SkipVerification"]).RadiusSecret);
        }
        finally
        {
            Env["RADIUS_SECRET"] = saved!;
        }
    }

    [Fact]
    public void Parses_dry_run_and_old_certificate_options()
    {
        var o = Parse(Example);
        Assert.False(o.DryRun);
        Assert.True(o.KeepOldCertificates);

        o = Parse([.. Example, "-WhatIf", "-DeleteOldCertificates"]);
        Assert.True(o.DryRun);
        Assert.False(o.KeepOldCertificates);

        Assert.Throws<CliArgumentException>(() => Parse([.. Example, "-DeleteOldCertificates", "-KeepOldCertificates"]));
    }
}

public class BackupArgumentTests
{
    private static readonly Dictionary<string, string> Env = new() { ["ISE_USERNAME"] = "user", ["ISE_PASSWORD"] = "pw" };

    [Fact]
    public void Backup_needs_only_the_admin_node_credentials_and_a_password()
    {
        var o = ArgumentParser.Parse(["-Backup", "-AdmNode", "ise", "-BackupDirectory", "b"], k => Env.GetValueOrDefault(k),
            k => k == ArgumentParser.SecretKeys.BackupPassword ? "Backup12345" : null);

        Assert.True(o.Backup);
        Assert.Equal(("b", "Backup12345"), (o.BackupDirectory, o.BackupPassword));
    }

    [Theory]
    [InlineData(null, "Backup password missing")]
    [InlineData("short", "at least 8")]
    public void Backup_password_is_required(string? password, string error)
    {
        var ex = Assert.Throws<CliArgumentException>(() => ArgumentParser.Parse(["-Backup", "-AdmNode", "ise"],
            k => k == "BACKUP_PASSWORD" ? password : Env.GetValueOrDefault(k)));
        Assert.Contains(error, ex.Message);
    }
}
