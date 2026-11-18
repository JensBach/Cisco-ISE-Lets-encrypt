# Configuration for Invoke-CiscoIseLetsEncrypt.ps1 (copy to jobs.psd1).
# Secrets are NOT stored here. They are kept in .NET user secrets of the account that runs the task
# (see Set-CiscoIseLetsEncryptSecrets.ps1).
@{
    # Folder with CiscoIseLetsEncrypt.exe. Default: the folder of the script.
    # ExePath       = 'C:\Program Files\CiscoIseLetsEncrypt\CiscoIseLetsEncrypt.exe'

    # Log folder (program logs + transcript of each run). Kept for LogRetentionDays.
    LogDirectory     = 'C:\ProgramData\CiscoIseLetsEncrypt\logs'
    LogRetentionDays = 90

    # Arguments added to every job.
    CommonArguments  = @(
        '-AdmNode', 'ise-pan.example.com'
        '-DnsChallengeUrl', 'https://dnsproxy.example.com'
        # '-AcmeTest'               # Let's Encrypt staging – remove for production
        # '-SkipIseTlsValidation'   # only if the server does not trust the ISE admin certificate
        # '-DeleteOldCertificates'  # default is to keep old certificates
    )

    # One job per certificate. The jobs run one after the other; one failing job does not stop the next.
    Jobs = @(
        @{
            Name      = 'EAP'
            Arguments = @(
                '-Roles', 'EAP,DTLS'
                '-CertificateDNS', 'eap.example.com'
                # Same certificate on several nodes (exported with its key from the first node):
                '-Node', 'ise-17-a.example.com,ise-17-b.example.com'
            )
        }
        # @{
        #     Name      = 'Portal'
        #     Arguments = @('-Roles', 'Portal', '-CertificateDNS', 'guest.example.com')
        # }
    )
}
