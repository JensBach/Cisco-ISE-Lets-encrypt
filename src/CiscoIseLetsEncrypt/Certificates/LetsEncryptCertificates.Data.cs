// Generated from https://letsencrypt.org/certificates/ and https://letsencrypt.org/docs/staging-environment/ (November 2026).
// Update when Let's Encrypt changes its hierarchy.
namespace CiscoIseLetsEncrypt.Certificates;

public static partial class LetsEncryptCertificates
{
    private static readonly KnownCa[] All =
    [
        new(AcmeEnvironment.Production, CaKeyType.RSA, CaKind.Root, "ISRG Root X1", "ISRG Root X1", "https://letsencrypt.org/certs/isrgrootx1.der",
            "MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAwTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5" +
            "IFJlc2VhcmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcG" +
            "A1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC" +
            "ggIBAK3oJHP0FDfzm54rVygch77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpm" +
            "ZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6UA5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sWT8KOEUt+zwvo/7V3LvSye0rg" +
            "TBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyHB5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UCB5iPNgiV5+I3lg02" +
            "dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUvKBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWnOlFuhjue" +
            "fXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTnjh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw" +
            "qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CIrU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIB" +
            "BjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkqhkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1" +
            "XIpu+ILlaS/V9lZLubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+" +
            "mvoiBOv/2X/qkSsisRcOj/KKNFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5ORAzI4JMPJ+GslWYHb4phowim57iaztX" +
            "OoJwTdwJx4nLCgdNbOhdjsnvzqvHu7UrTkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdCjNPElpzVmbUq4JUagEiuTDkH" +
            "zsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVcoyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq4RgqsahDYVvTH9w7" +
            "jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPAmRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57demyPxgcY" +
            "xn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc="),
        new(AcmeEnvironment.Production, CaKeyType.RSA, CaKind.Root, "ISRG Root YR", "ISRG Root YR (self-signed)", "https://letsencrypt.org/certs/gen-y/root-yr.der",
            "MIIFKTCCAxGgAwIBAgIRAOxGNJNgz0sP+KmC2Tqpyj0wDQYJKoZIhvcNAQELBQAwLjELMAkGA1UEBhMCVVMxDTALBgNVBAoTBElTUkcxEDAOBgNVBAMTB1Jv" +
            "b3QgWVIwHhcNMjUwOTAzMDAwMDAwWhcNNDUwOTAyMjM1OTU5WjAuMQswCQYDVQQGEwJVUzENMAsGA1UEChMESVNSRzEQMA4GA1UEAxMHUm9vdCBZUjCCAiIw" +
            "DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANvGJnN78CTJdWL3+eGfsLN5TrNBJs+VH9hRXqRbwxu9sGNiB0BD1fcOxbSUQCJIM1xE13Db+5Cw1w0s0EBY" +
            "svuIP/6joF0w8cuImbgR1OGgYbSQ4OpzI+DG8SGuTlcE873OCS+kh3srlo6vl43M5OJg4Aeo1sfHp6kTJDoIiFBNJAY+OKfX/FUvYKuhjT+no49lmqmupSBI" +
            "5PkBQiqrEGtWU5uxU/cQWHGu8jSjFBznZqvbNPLMXMLFxCb3WTfrJBXXjqvWG+v4bjzxjjeAtOlU7qarRDvNOyAuQYLln904M+faKx8hnLCpJ15ZqaEgcNlY" +
            "+9MMWcC5yvL2A2j3l9+2buggZX+dOE91zYmIdawTvSZuVvlbRrAlLxIB6pwMBjneXCjYQ8+3BCCjssbSNpZU3hTcBDdhfAlEDlYr6pEatnMdmDT5BqnKC92b" +
            "d0EhM1fbLHioLccLCuievT8ZkPhZrq7Mii7gNXAcUEAR8+lzYal+9zTg7C5DALyVOeG/CqfRAMn1KSHCR0NSA6P8tn/mGRlnCct5rtVCLnVySVpU6H1qGg3D" +
            "gTOuskf8eahTMiYbI5ezPJmO5ertalskQ1utp74+eDy92PI4ftHKTbq9IWhH4YZKh3WnJEIt+oQvlYZbY8tpEroKrFB6PFGzrJIDRyts4HqvuH52RFj2zv/B" +
            "AgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTe51tg0CJtQCh9Pw0B/qS1UrRRlDANBgkqhkiG9w0BAQsFAAOC" +
            "AgEAWHnf713Bdkq7t5yN2dNIgQakUb94X9WuyhMEHHkgx4oDpSUlnG0w4g94MoqaEUE31ZjRLU7L5LD1g9ujFHTQu8AD215AHMVQFbm6j8hQxdXHAzDajFNQ" +
            "nOlDJrLjzIx176oyAjvUtejZx2NNmdb5fd0WGVGsCdoAJ3N8ozo7ajE8t6vfxStZb4BQ9WYJGHUDrv2Ni5tJF6CNiPnlzs3BUfECRbE4JSk+jvy8+VoGiFE8" +
            "qsH/j78x2fjgQhAQFV7P7ZxydBTZ1wEkNpZNW2qnaK1SKBLa+xf6E06YRIq5uaI+HWH8SY1y5VbRgzq40EKg3yxP06fz+uYAUIFJoLNfhwRCc3Q6pQVuMX3y" +
            "AjHAes4gk4moGcLQ5p7HAh39yeylZc1J41sx/jKwLIkPE6Rr1Nf4pxdsxf9SA4yOEiAkDgq04DVxn8hgYFdUtBCuiuVC2heAEiqVEa+8QZjuw8Gj0EbHXcRd" +
            "1nInvGqRS1o9Is7YBdQN57X1AYveGBNNqjICSb7cawuw1EawTDrs13VUlJVEsbQ0/O/1aaV73mCdOQ8azqL2KTv1Ewu1xbquE2S+kdQUTo9TUwat3wUA6cwX" +
            "h1EfpS/3fJ0aGah5hdpRyoCLDlsSn8tkrjMfFFX0viC+GxHcsI1ANRYvqSFC2X1VRZfDg+wD6E21BccmifG4yWc="),
        new(AcmeEnvironment.Production, CaKeyType.RSA, CaKind.Root, "ISRG Root YR", "ISRG Root YR (cross-signed by ISRG Root X1)", "https://letsencrypt.org/certs/gen-y/root-yr-by-x1.der",
            "MIIF9DCCA9ygAwIBAgIRAPJLbRf52a18scn+p4eCaZ8wDQYJKoZIhvcNAQELBQAwTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5" +
            "IFJlc2VhcmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjYwNTEzMDAwMDAwWhcNMzIwOTAyMjM1OTU5WjAuMQswCQYDVQQGEwJVUzENMAsG" +
            "A1UEChMESVNSRzEQMA4GA1UEAxMHUm9vdCBZUjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANvGJnN78CTJdWL3+eGfsLN5TrNBJs+VH9hRXqRb" +
            "wxu9sGNiB0BD1fcOxbSUQCJIM1xE13Db+5Cw1w0s0EBYsvuIP/6joF0w8cuImbgR1OGgYbSQ4OpzI+DG8SGuTlcE873OCS+kh3srlo6vl43M5OJg4Aeo1sfH" +
            "p6kTJDoIiFBNJAY+OKfX/FUvYKuhjT+no49lmqmupSBI5PkBQiqrEGtWU5uxU/cQWHGu8jSjFBznZqvbNPLMXMLFxCb3WTfrJBXXjqvWG+v4bjzxjjeAtOlU" +
            "7qarRDvNOyAuQYLln904M+faKx8hnLCpJ15ZqaEgcNlY+9MMWcC5yvL2A2j3l9+2buggZX+dOE91zYmIdawTvSZuVvlbRrAlLxIB6pwMBjneXCjYQ8+3BCCj" +
            "ssbSNpZU3hTcBDdhfAlEDlYr6pEatnMdmDT5BqnKC92bd0EhM1fbLHioLccLCuievT8ZkPhZrq7Mii7gNXAcUEAR8+lzYal+9zTg7C5DALyVOeG/CqfRAMn1" +
            "KSHCR0NSA6P8tn/mGRlnCct5rtVCLnVySVpU6H1qGg3DgTOuskf8eahTMiYbI5ezPJmO5ertalskQ1utp74+eDy92PI4ftHKTbq9IWhH4YZKh3WnJEIt+oQv" +
            "lYZbY8tpEroKrFB6PFGzrJIDRyts4HqvuH52RFj2zv/BAgMBAAGjgeswgegwDgYDVR0PAQH/BAQDAgEGMBMGA1UdJQQMMAoGCCsGAQUFBwMBMA8GA1UdEwEB" +
            "/wQFMAMBAf8wHQYDVR0OBBYEFN7nW2DQIm1AKH0/DQH+pLVStFGUMB8GA1UdIwQYMBaAFHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAi" +
            "BggrBgEFBQcwAoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzATBgNVHSAEDDAKMAgGBmeBDAECATAnBgNVHR8EIDAeMBygGqAYhhZodHRwOi8veDEuYy5sZW5j" +
            "ci5vcmcvMA0GCSqGSIb3DQEBCwUAA4ICAQA8spSI95KKfn2W6GMmDpHBJSPaLbsS3W93cijJCRCYAc1fsJgL1FIL7C0C9ecPOdcwB2fi0Dk2p94j9iTJCxmt" +
            "5CFSKLRWwnXT2MMSXexVxqoVB79BdWPxVXETkVme/qYSAuKVHh5Ps+5BixgmwS1JkjSAc+MfrUbNssVEEnH0aEiAh+rotXAVJSP/Ye7LJPEwD9DWG72vVWbh" +
            "AcuOf5OLjz57Ctk7MgQHynZ7+PlHJtajroCaIbtCr6tcZZaAwUQm+jQyeWdV+2hv9deOYFmKeQyjjcSrN5Nadrw+L9DZJLbA1HqeNvLhBgqpP0fvJq2N6EtD" +
            "574N6eMI7uMsJTnji2UDz9el5XLSv9fqJMuDQtYVb2oTNoKpoUqhxPVC0aq4eG5MESaIdn8b5ZGSSeAJLMHXljEdlNza+ncfkviXk1POLnnFdvx8/gk6M374" +
            "WbLWFXw8N141B/Rl/tINGfl1TxOIiqtiMYkL02RSGb1kq34BL9NPP27zRGMuHGnzS3hFIrRTfKxrzUZ9RzQWzEG3K6fJ3r2nqSltkeytis9DIBoFY9VmVyjL" +
            "M71DMi+y1+TRSJVClEMwvA4yL++7q9XZx5r5wBRWB4kQTKH5qyoZnDw7iiuh1lIDyDFx8r7i9vIJU5HS3moZLkYWAOilMaV9N56A9Bgb6dNcHkvg3NoaYA=="),
        new(AcmeEnvironment.Production, CaKeyType.RSA, CaKind.Intermediate, "YR1", "Let's Encrypt YR1", "https://letsencrypt.org/certs/gen-y/int-yr1.der",
            "MIIE2zCCAsOgAwIBAgIRAKICU/FfJpHAXcHOE7m8yk4wDQYJKoZIhvcNAQELBQAwLjELMAkGA1UEBhMCVVMxDTALBgNVBAoTBElTUkcxEDAOBgNVBAMTB1Jv" +
            "b3QgWVIwHhcNMjUwOTAzMDAwMDAwWhcNMjgwOTAyMjM1OTU5WjAzMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3MgRW5jcnlwdDEMMAoGA1UEAxMDWVIx" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoVi8X2xCYgMXvJxNPKp/oF13UMgmPABB07VCLNDtoXmt9luEZNJSBV10VyT1Pz6LD8Zq1d2gc43W" +
            "Nl1AdRrj4sEnazbOiz0nPpmGBp2hui49oZtDIY6wdKeZAi5BbNU20CH6RSBBMLSQ9cXrH8dxdv4PAJ45ssGML68USE3BsjC2a6cAN9L5CgXVIQi5tfNiTPoF" +
            "ZZ3S0OlXqLmmtdV95udWAb5b6e/F49DiCsH0Y00Ag72BVIb1hzynmKe+X0mERBTtsb3BwmpV9ipeBjMLoR/D9cHxHQCWoi5lTmXwY015J5rGelz1nZjJuxc2" +
            "kioaX29XJBnhMkP531rSdG5uMwIDAQABo4HuMIHrMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDATASBgNVHRMBAf8ECDAGAQH/AgEAMB0G" +
            "A1UdDgQWBBQfLzW+RhSCzUCxrnksVXj699Ro+zAfBgNVHSMEGDAWgBTe51tg0CJtQCh9Pw0B/qS1UrRRlDAyBggrBgEFBQcBAQQmMCQwIgYIKwYBBQUHMAKG" +
            "Fmh0dHA6Ly95ci5pLmxlbmNyLm9yZy8wEwYDVR0gBAwwCjAIBgZngQwBAgEwJwYDVR0fBCAwHjAcoBqgGIYWaHR0cDovL3lyLmMubGVuY3Iub3JnLzANBgkq" +
            "hkiG9w0BAQsFAAOCAgEA0+zvMq3kHig1ddTmmm+RibTr9/RpX7k4buanMMRqbV/yIvP82zAHN3mvaw+cASuVsdpd0ikjhr4hnhJQLQOzOp2ccKrsdGOAgo0v" +
            "ddeISFAqEWEV4lmUM3vFF796up+bSgmJ1u6RupDCMxDgF8M3eLvGuj6L0lu3zkQ0KuQLnKxLtB0oQqn1Idg5CuuGpMvQzk29Pa3D/qHurc0EIM9SxukQuJqq" +
            "63lxsYyRQFU8yMBOhq1w5LbfaWNRrz1uklOfI/pYkAb2E2MTZrAMQkBIE2S8Jt1F8gRc96o/xOsrgvSka84AisX6xq1lz1Z7jGvrnXc4TMcjxZTjiTaihcYI" +
            "1JIXZiLtEMSCa5l3cu8YWd6zdLRQlqRdclVjuQfNHawRJ6GWlkK0QJosivTKwdBw3KxEtzGo8yMHERbsy57gP1UXHOMcmZYQC0gtyR3SxfenIM/MxC3Ia2Yp" +
            "ab/kQ/CTnlIn2KQ5JUC6NYrGCbhFN9bp5lKJStEwCUnLpntcrXk5XVDCNv/5RyWpRThkGOV7GetKkQ0qAY8hCzWK6oqnAhDZcjlYVdWfqOw3DIOX6EDNBgAq" +
            "HarRVxyF9QZdOaXSyPJ0ueD2BYJEBgaCGQ8rAaU/Qc123V5LTXDZW4CcsPBDyhy4v+c8hClAyw/IkJlfBqxB9D+/wvIMHgECZ4ptP6o="),
        new(AcmeEnvironment.Production, CaKeyType.RSA, CaKind.Intermediate, "YR2", "Let's Encrypt YR2", "https://letsencrypt.org/certs/gen-y/int-yr2.der",
            "MIIE2jCCAsKgAwIBAgIQTr0klH4k05SALYSlL9WzGTANBgkqhkiG9w0BAQsFADAuMQswCQYDVQQGEwJVUzENMAsGA1UEChMESVNSRzEQMA4GA1UEAxMHUm9v" +
            "dCBZUjAeFw0yNTA5MDMwMDAwMDBaFw0yODA5MDIyMzU5NTlaMDMxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQwwCgYDVQQDEwNZUjIw" +
            "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDZ0LxwBppqh84luqMerV/eeL/fXQ7mLQQv1LnpWKZbyvGpx6wh6AfnslAnF6ewTkcHA+gSOoBvm3Df" +
            "m06AuGiF+KRut4fAcowqnAQQCW98+QPP/eOv/wug7Iyk4NkOxf2I6g2f55T6nJoOTLFcukeRq80JGQEYan+dPFr9OGUgQK2hGKgNkW87pappsOAuUJcroYhR" +
            "t5uUis4qaZireiseu32gzDJNBAiKtsvd6HX4v25bpkRNcS/B/Gtc9kVbUpD+2PLPxdei3Tim55k4tfAEXwD2qyiPTxrTNq6lN+AMr5g2c1dNqkOTwjxeV6L5" +
            "lpP1rGiYvLnRaPlOqyZRPW+5AgMBAAGjge4wgeswDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYD" +
            "VR0OBBYEFEAVLSZ57TIgnt+ach3WMh+BDIEMMB8GA1UdIwQYMBaAFN7nW2DQIm1AKH0/DQH+pLVStFGUMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcwAoYW" +
            "aHR0cDovL3lyLmkubGVuY3Iub3JnLzATBgNVHSAEDDAKMAgGBmeBDAECATAnBgNVHR8EIDAeMBygGqAYhhZodHRwOi8veXIuYy5sZW5jci5vcmcvMA0GCSqG" +
            "SIb3DQEBCwUAA4ICAQB0ZUQWZ9/Yn9COEpo+JfecMnB0h0vwDm/M66IqXqw3LoaLmx9lZvRTeDIS67PUeI3yCA2W6PKRD0/FE/G57lOmS+Xy5AaaL00ICGOq" +
            "jNcCaMWW8o8nevHOd4i4lqgtznE/28QwlcdJyF8yBiWHpnyjhEpmNWJURgOCOg2xpwRMBCsjMScqYPtOhBeuYQvSwAEeTML2Ukh6uGuX4E14q65Ja8cdjF5b" +
            "AldnP1eE4FBaAwsZG2fOqqrKV03Y85Nw2btedP1AtliQuJZs/Jo/gXxXdc7LrH3McgnpnbTiAncX7yEShP6kzQejllqMCIt52HOjxDGWafS7Xw+DKwqmH+Eq" +
            "y8dcbOuag/1AYlQoKNVK3F5qHh6tEDiMqQcLIibGKteE6iHo4A/bIScbzrhXUYuism42ZYzmc48FMVIH3qy4L84ETdAH2gtxw0PAhvRVXp8HP7wfngpzsN/8" +
            "xOTpeRSbM4+Qbc56G6+Bifmv6sk1ieQbNA3wJdl4DDUuQSV8hBgx6zoI1ZSGORprDFux7c6rhc77QZMSRrEgomBeklervEve86ylWmZ3WWHV6RLMi8xNvjd7" +
            "1r4EPIGgY7BZU/VPBkq+uA7Gb6mbJnFgV43uh3xyLRFgxIAphIukwTGSMZZR+AI+Qnp0BYTWovHXozOf3H8r6hozEoT02JHn0AeTfA=="),
        new(AcmeEnvironment.Production, CaKeyType.RSA, CaKind.Backup, "YR3", "Let's Encrypt YR3 (backup)", "https://letsencrypt.org/certs/gen-y/int-yr3.der",
            "MIIE2jCCAsKgAwIBAgIQdv2+nJw5pmI1PsQaDsOT/jANBgkqhkiG9w0BAQsFADAuMQswCQYDVQQGEwJVUzENMAsGA1UEChMESVNSRzEQMA4GA1UEAxMHUm9v" +
            "dCBZUjAeFw0yNTA5MDMwMDAwMDBaFw0yODA5MDIyMzU5NTlaMDMxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQwwCgYDVQQDEwNZUjMw" +
            "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJS0+QyfrZm8U0nXugJKg+3nraHoxKN9NOsGvHT9NtcdgThWuj6gizDMqn9VQilyPJ+qKK7rjgBM/X" +
            "K3ogx61EPbgQY8LiVNn4nsmR1UFUdalb/cL/mYtXo3lu3qop7k6Ol+pOLzvlBINhl+Mq7l9VxUCM717UpYumNKxGNRjALGg5H16C93UQlW8KgRpW58fY5Be3" +
            "cLqv24bbKRFisb7S/HPA967pW6rAO/DFFKbi35NfHKEG0jIGqxtsbYbK+/0qe2147p9oUO/SNcuaT9poLFWKmcY90UR0hXKy+qiR6Kv7/e5gCK/BGkjLXM1A" +
            "fX1CRDwOiIPPsK+RJOIj00ilAgMBAAGjge4wgeswDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYD" +
            "VR0OBBYEFGllKfkz+Am2QtXh87W1nR9feiJ8MB8GA1UdIwQYMBaAFN7nW2DQIm1AKH0/DQH+pLVStFGUMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcwAoYW" +
            "aHR0cDovL3lyLmkubGVuY3Iub3JnLzATBgNVHSAEDDAKMAgGBmeBDAECATAnBgNVHR8EIDAeMBygGqAYhhZodHRwOi8veXIuYy5sZW5jci5vcmcvMA0GCSqG" +
            "SIb3DQEBCwUAA4ICAQCNj5bxci8knkGgfw3qSv0KbbjZpmKUgZzgYYW6EpiFj4Bx8CTQ79RCEuitFdGFOvG9xfQdWArQlaO/bsmNcsz0D9wiuwxc9RCo6JC4" +
            "BKRMcmKEfRiLzHWwHZfUj0sCAY0yBryOGL80J3sD2C3mjAFwV2mVIeuVKOhQeTcstVceW97+38AC+juHSq+xu/HuCbX0LgTzMzh8RYy8OtO80IFE2v8qAEDI" +
            "K2PYoQp27nwftAICAtOoGzqHDJqPWeiSTQgt1ndRgGAmV7H0HssX66i8naQFlsiidol4goFYEVMVJArpg2X5NyumCCX/aSnXKgp8leQ6XoVQz0VI6+k1a0go" +
            "PUJB7xp67BkCxkwJamDOMpQLxpdTPI2Z1TO2BuEyzBd8DC/yfm1+rvMCRG3AX44f0ra2ueiM7cdRvzcE+b3c2fun1n/4xzigiimm8Rzs6Cc0A59mt3XhruOe" +
            "+zGIXtJgn0wf9XfJhKdKcdEH5VNhFapnGc9Tm+fd4n5Qojd7W2CwdBUBgwYIt4Cqxqr2OEf7/k1Xm8eplMQlhwySs/hM0dY6csOPNIXeJm1YsnJyxUGvKRWj" +
            "On+vC9k1SXilnnwhcIs9Pp9e5bckYAnB79VJXN/L8X8xt/9Qm2xmKKe/xzKA+oRvWKofeFGKU7hcnFbyUwlCu0d+JkgWxQu4x4drcQ=="),
        new(AcmeEnvironment.Production, CaKeyType.ECDSA, CaKind.Root, "ISRG Root X1", "ISRG Root X1", "https://letsencrypt.org/certs/isrgrootx1.der",
            "MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAwTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5" +
            "IFJlc2VhcmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcG" +
            "A1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC" +
            "ggIBAK3oJHP0FDfzm54rVygch77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpm" +
            "ZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6UA5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sWT8KOEUt+zwvo/7V3LvSye0rg" +
            "TBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyHB5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UCB5iPNgiV5+I3lg02" +
            "dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUvKBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWnOlFuhjue" +
            "fXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTnjh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw" +
            "qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CIrU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIB" +
            "BjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkqhkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1" +
            "XIpu+ILlaS/V9lZLubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+" +
            "mvoiBOv/2X/qkSsisRcOj/KKNFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5ORAzI4JMPJ+GslWYHb4phowim57iaztX" +
            "OoJwTdwJx4nLCgdNbOhdjsnvzqvHu7UrTkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdCjNPElpzVmbUq4JUagEiuTDkH" +
            "zsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVcoyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq4RgqsahDYVvTH9w7" +
            "jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPAmRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57demyPxgcY" +
            "xn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc="),
        new(AcmeEnvironment.Production, CaKeyType.ECDSA, CaKind.Root, "ISRG Root X2", "ISRG Root X2 (self-signed)", "https://letsencrypt.org/certs/isrg-root-x2.der",
            "MIICGzCCAaGgAwIBAgIQQdKd0XLq7qeAwSxs6S+HUjAKBggqhkjOPQQDAzBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVz" +
            "ZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw00MDA5MTcxNjAwMDBaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQK" +
            "EyBJbnRlcm5ldCBTZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgyMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CDCuwJ" +
            "SvMWSj5cz3es3mcFDR0HttwW+1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7AlF9ItgKbppbd9/w+kHsOdx1ymgHDB/qo0Iw" +
            "QDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUfEKWrt5LSDv6kviejM9ti6lyN5UwCgYIKoZIzj0EAwMDaAAwZQIwe3lORlCE" +
            "wkSHRhtFcP9Ymd70/aTSVaYgLXTWNLxBo1BfASdWtL4ndQavEi51mI38AjEAi/V3bNTIZargCyzuFJ0nN6T5U6VR5CmD1/iQMVtCnwr1/q4AaOeMSQ+2b1tb" +
            "FfLn"),
        new(AcmeEnvironment.Production, CaKeyType.ECDSA, CaKind.Root, "ISRG Root X2", "ISRG Root X2 (cross-signed by ISRG Root X1)", "https://letsencrypt.org/certs/gen-y/root-x2-by-x1.der",
            "MIIEcDCCAligAwIBAgIQbI8dxyfHEX97r4U6yYD5zTANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkg" +
            "UmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMTAeFw0yNjA1MTMwMDAwMDBaFw0zMjA5MDIyMzU5NTlaME8xCzAJBgNVBAYTAlVTMSkwJwYD" +
            "VQQKEyBJbnRlcm5ldCBTZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgyMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CD" +
            "CuwJSvMWSj5cz3es3mcFDR0HttwW+1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7AlF9ItgKbppbd9/w+kHsOdx1ymgHDB/q" +
            "o4H1MIHyMA4GA1UdDwEB/wQEAwIBBjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUfEKWrt5LSDv6" +
            "kviejM9ti6lyN5UwHwYDVR0jBBgwFoAUebRZ5nu25eQBc4AIiMgaWPbpm24wMgYIKwYBBQUHAQEEJjAkMCIGCCsGAQUFBzAChhZodHRwOi8veDEuaS5sZW5j" +
            "ci5vcmcvMBMGA1UdIAQMMAowCAYGZ4EMAQIBMCcGA1UdHwQgMB4wHKAaoBiGFmh0dHA6Ly94MS5jLmxlbmNyLm9yZy8wDQYJKoZIhvcNAQELBQADggIBAD2/" +
            "e9frmMxNpCV03qUHegg+MV2wz9644YoXdqtH8RyWYcBO7xfjjGEXdU1e/o0OkEFiynUCOSIk/vLLo7ttz6CPAeNlWfC0XNkoGeWgK6jjXvozBaGuGH5n0Ufo" +
            "shMeWTuURqNN5G00sSXDTBrpp2+mgvdZQjb8K11TYMA25QA+YHNfbIEL0BniAhKS2gsnJjSzrdZLI+EZ7SEyqdR2rkjd1KutLDU+n3TFyxjniZVGur4YlhMP" +
            "3mY/dV95IruAkkjOZier6hGBdEgZXXvaCz9u9iVEadsIE75pAGL8oHV5vxdARDiotRpul1IN/UZwzAbrfUFcw1HkAcYD/mlZfnQ2ieCF2MS7j3Vhv7JPDKp4" +
            "5fmykmzYNSrumRW0upFFKDBOoF7hsOb7oLyHS+Uft6jOUfOrogj8YUx38hKb2K20r42OgsSdDdxdeYWcMS3Sb6mwJeSZEYxJ2gaXnDSPaKhhrNkYwljyVQyr" +
            "4Nq+MEJytXNTnHqaAcrNwZlVpcJL1KBnMrMjP7eanvUwL3FYj3cF17jtboLt7gLoi4+2rWZFvn+w54jmd/FIuhhZcEaU/wvU6BUNMtcVquVGHp7itQeDth5j" +
            "+XL3j4WJ2SABwzUl6OeYdgpIt/ITZa+pTT0mQ/r5XyA4MEAiabn7XJjvCERlF2dcn2wqJw+CreTkkQ2R"),
        new(AcmeEnvironment.Production, CaKeyType.ECDSA, CaKind.Root, "ISRG Root YE", "ISRG Root YE (self-signed)", "https://letsencrypt.org/certs/gen-y/root-ye.der",
            "MIIB2TCCAWCgAwIBAgIRAKQCa6LvbHwg1AR+XmWmk4AwCgYIKoZIzj0EAwMwLjELMAkGA1UEBhMCVVMxDTALBgNVBAoTBElTUkcxEDAOBgNVBAMTB1Jvb3Qg" +
            "WUUwHhcNMjUwOTAzMDAwMDAwWhcNNDUwOTAyMjM1OTU5WjAuMQswCQYDVQQGEwJVUzENMAsGA1UEChMESVNSRzEQMA4GA1UEAxMHUm9vdCBZRTB2MBAGByqG" +
            "SM49AgEGBSuBBAAiA2IABDwS/6vhrcVqcbBo+wgdI3fwn9x7DNJJOY/lTOti0vkwuRN87RhEhTH17E7XyFjWsPYhIPt/wzOqxTd2b+4ZJNy9ID04YywF9U5z" +
            "asDVyGSNErVNtz8uSGh5izW87j77GaNCMEAwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFKPIJlqOoUzQNWP8myPIOq5W809W" +
            "MAoGCCqGSM49BAMDA2cAMGQCMHhMr8N9LdL1VQKs9BdV81r76eXRB6mtjuNjzk6/lBsPNToWLTDzGYgtQKO1jl63uAIwGV7monyF377c+MM1oqVNs17sgu7F" +
            "9YKZwgLmVbeOMDbKAXHtKMDLbiGllCcs8f47"),
        new(AcmeEnvironment.Production, CaKeyType.ECDSA, CaKind.Root, "ISRG Root YE", "ISRG Root YE (cross-signed by ISRG Root X2)", "https://letsencrypt.org/certs/gen-y/root-ye-by-x2.der",
            "MIICpjCCAiugAwIBAgIRAIchZfw0tuX7qK3Vs3BftTowCgYIKoZIzj0EAwMwTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJl" +
            "c2VhcmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDIwHhcNMjYwNTEzMDAwMDAwWhcNMzIwOTAyMjM1OTU5WjAuMQswCQYDVQQGEwJVUzENMAsGA1UE" +
            "ChMESVNSRzEQMA4GA1UEAxMHUm9vdCBZRTB2MBAGByqGSM49AgEGBSuBBAAiA2IABDwS/6vhrcVqcbBo+wgdI3fwn9x7DNJJOY/lTOti0vkwuRN87RhEhTH1" +
            "7E7XyFjWsPYhIPt/wzOqxTd2b+4ZJNy9ID04YywF9U5zasDVyGSNErVNtz8uSGh5izW87j77GaOB6zCB6DAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYI" +
            "KwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUo8gmWo6hTNA1Y/ybI8g6rlbzT1YwHwYDVR0jBBgwFoAUfEKWrt5LSDv6kviejM9ti6lyN5Uw" +
            "MgYIKwYBBQUHAQEEJjAkMCIGCCsGAQUFBzAChhZodHRwOi8veDIuaS5sZW5jci5vcmcvMBMGA1UdIAQMMAowCAYGZ4EMAQIBMCcGA1UdHwQgMB4wHKAaoBiG" +
            "Fmh0dHA6Ly94Mi5jLmxlbmNyLm9yZy8wCgYIKoZIzj0EAwMDaQAwZgIxAMU19WCtmxVND8UHBZRoma49Z7jPs64Dma0eTu1OChVbB/2J7GV3nvYKAx54uk1G" +
            "9QIxAO0miLVJu8PLNiXXXkiE/gsK3CTRTF/aeo4bMX42Zw40csRU6AC26hSW1/IWaas6dg=="),
        new(AcmeEnvironment.Production, CaKeyType.ECDSA, CaKind.Intermediate, "YE1", "Let's Encrypt YE1", "https://letsencrypt.org/certs/gen-y/int-ye1.der",
            "MIICizCCAhGgAwIBAgIQXd1w3TH4AchcGGp6BLgK/jAKBggqhkjOPQQDAzAuMQswCQYDVQQGEwJVUzENMAsGA1UEChMESVNSRzEQMA4GA1UEAxMHUm9vdCBZ" +
            "RTAeFw0yNTA5MDMwMDAwMDBaFw0yODA5MDIyMzU5NTlaMDMxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQwwCgYDVQQDEwNZRTEwdjAQ" +
            "BgcqhkjOPQIBBgUrgQQAIgNiAAQHZVB1/mimla2hfSurylScjPMZaOJXLz/NnAc2sylm8WDyhU9Ccp+zASQi5vSwGGJjSGklkD9fdPR8GpyDIOIjCEfrnbt/" +
            "v+ZSEPLLEGbaM6EccDbN7p9xteIm2Avf+ryjge4wgeswDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYBAf8CAQAw" +
            "HQYDVR0OBBYEFLsgykcL/tflnPmPCSqjjDdFsbzYMB8GA1UdIwQYMBaAFKPIJlqOoUzQNWP8myPIOq5W809WMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw" +
            "AoYWaHR0cDovL3llLmkubGVuY3Iub3JnLzATBgNVHSAEDDAKMAgGBmeBDAECATAnBgNVHR8EIDAeMBygGqAYhhZodHRwOi8veWUuYy5sZW5jci5vcmcvMAoG" +
            "CCqGSM49BAMDA2gAMGUCMQDgjUEahFT/h3DRakqiPZpLvPgfZwkt6K2EOMmh1nvEzl83eMLYcod4GCl3b0J1Nn0CMBNYmEQJb4CEG5WoOe7aRn/LVKu6saHm" +
            "HEynI7ysIPd8zQsK1HdmhlHKlw9Z5GpGvA=="),
        new(AcmeEnvironment.Production, CaKeyType.ECDSA, CaKind.Intermediate, "YE2", "Let's Encrypt YE2", "https://letsencrypt.org/certs/gen-y/int-ye2.der",
            "MIICjDCCAhGgAwIBAgIQTfOxXdbAeExQfNN7WObxFTAKBggqhkjOPQQDAzAuMQswCQYDVQQGEwJVUzENMAsGA1UEChMESVNSRzEQMA4GA1UEAxMHUm9vdCBZ" +
            "RTAeFw0yNTA5MDMwMDAwMDBaFw0yODA5MDIyMzU5NTlaMDMxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQwwCgYDVQQDEwNZRTIwdjAQ" +
            "BgcqhkjOPQIBBgUrgQQAIgNiAARxmrQzkdbEEL3MqXt3dJQttYc47axkdDTHud5TPqM2z5uSD5cmk0WrHlWXvnlvqBLqiB34kluxIbmMyAiq3/YD6e80/vV2" +
            "59K8XQIdjFXloYOa0mIU71f7HQ09PvYDlw+jge4wgeswDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYBAf8CAQAw" +
            "HQYDVR0OBBYEFLlZ8o7PIvCG0zdI/3YUGLqC2FWHMB8GA1UdIwQYMBaAFKPIJlqOoUzQNWP8myPIOq5W809WMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw" +
            "AoYWaHR0cDovL3llLmkubGVuY3Iub3JnLzATBgNVHSAEDDAKMAgGBmeBDAECATAnBgNVHR8EIDAeMBygGqAYhhZodHRwOi8veWUuYy5sZW5jci5vcmcvMAoG" +
            "CCqGSM49BAMDA2kAMGYCMQDIcnw5dcZLN9ffynXnnkLD/itSJEycJPb3sRkzeqBowup7vOsAwaqoCnNn/jh9wycCMQCJM6CPlaOC4pQYYbJtVPYbDKrIb2EK" +
            "k5NpOpE6/XttQYZV/3gilB9l+Cc/DOVwmyg="),
        new(AcmeEnvironment.Production, CaKeyType.ECDSA, CaKind.Backup, "YE3", "Let's Encrypt YE3 (backup)", "https://letsencrypt.org/certs/gen-y/int-ye3.der",
            "MIICizCCAhGgAwIBAgIQLTM7c3DEJq+3k6hXVBAwZzAKBggqhkjOPQQDAzAuMQswCQYDVQQGEwJVUzENMAsGA1UEChMESVNSRzEQMA4GA1UEAxMHUm9vdCBZ" +
            "RTAeFw0yNTA5MDMwMDAwMDBaFw0yODA5MDIyMzU5NTlaMDMxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQwwCgYDVQQDEwNZRTMwdjAQ" +
            "BgcqhkjOPQIBBgUrgQQAIgNiAAS7HaCvDM9Y3aYPW+iH6uUTK2KFUYx0vye5xK1KNTWZUgloiW2budqzvCQaarmJTNujiV+ZrWrOpox+N4kTsiCec6yfw7VG" +
            "mErLC5ZSq2X4d2vJc1g8VIU3fb7CuzJ/bDOjge4wgeswDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYBAf8CAQAw" +
            "HQYDVR0OBBYEFPaiftZeI2/d3UVGYR6CFXXN8eaOMB8GA1UdIwQYMBaAFKPIJlqOoUzQNWP8myPIOq5W809WMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw" +
            "AoYWaHR0cDovL3llLmkubGVuY3Iub3JnLzATBgNVHSAEDDAKMAgGBmeBDAECATAnBgNVHR8EIDAeMBygGqAYhhZodHRwOi8veWUuYy5sZW5jci5vcmcvMAoG" +
            "CCqGSM49BAMDA2gAMGUCMHD5+4lU6i9k7inE4Opkebs+IFjYjlD9BNaPyQe9/hBSjOOTaF5UZzlNy64JID6VUwIxANr7lTvWWzlGU1PpCR7lfDVXtmGgr3dP" +
            "HkigUXaTWbbLrx84pOAdd3FEGJM2Kf5etA=="),
        new(AcmeEnvironment.Staging, CaKeyType.RSA, CaKind.Root, "(STAGING) Pretend Pear X1", "(STAGING) Pretend Pear X1", "https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x1.der",
            "MIIFmDCCA4CgAwIBAgIQU9C87nMpOIFKYpfvOHFHFDANBgkqhkiG9w0BAQsFADBmMQswCQYDVQQGEwJVUzEzMDEGA1UEChMqKFNUQUdJTkcpIEludGVybmV0" +
            "IFNlY3VyaXR5IFJlc2VhcmNoIEdyb3VwMSIwIAYDVQQDExkoU1RBR0lORykgUHJldGVuZCBQZWFyIFgxMB4XDTE1MDYwNDExMDQzOFoXDTM1MDYwNDExMDQz" +
            "OFowZjELMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1cml0eSBSZXNlYXJjaCBHcm91cDEiMCAGA1UEAxMZKFNUQUdJTkcp" +
            "IFByZXRlbmQgUGVhciBYMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALbagEdDTa1QgGBWSYkyMhscZXENOBaVRTMX1hceJENgsL0Ma49D3Mil" +
            "I4KS38mtkmdF6cPWnL++fgehT0FbRHZgjOEr8UAN4jH6omjrbTD++VZneTsMVaGamQmDdFl5g1gYaigkkmx8OiCO68a4QXg4wSyn6iDipKP8utsE+x1E28SA" +
            "75HOYqpdrk4HGxuULvlr03wZGTIf/oRt2/c+dYmDoaJhge+GOrLAEQByO7+8+vzOwpNAPEx6LW+crEEZ7eBXih6VP19sTGy3yfqK5tPtTdXXCOQMKAp+gCj/" +
            "VByhmIr+0iNDC540gtvV303WpcbwnkkLYC0Ft2cYUyHtkstOfRcRO+K2cZozoSwVPyB8/J9RpcRK3jgnX9lujfwA/pAbP0J2UPQFxmWFRQnFjaq6rkqbNEBg" +
            "Ly+kFL1NEsRbvFbKrRi5bYy2lNms2NJPZvdNQbT/2dBZKmJqxHkxCuOQFjhJQNeO+Njm1Z1iATS/3rts2yZlqXKsxQUzN6vNbD8KnXRMEeOXUYvbV4lqfCf8" +
            "mS14WEbSiMy87GB5S9ucSV1XUrlTG5UGcMSZOBcEUpisRPEmQWUOTWIoDQ5FOia/GI+Ki523r2ruEmbmG37EBSBXdxIdndqrjy+QVAmCebyDx9eVEGOIpn26" +
            "bW5LKerumJxa/CFBaKi4bRvmdJRLAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBS182Xy/rAKkh/7PH3zRKCs" +
            "YyXDFDANBgkqhkiG9w0BAQsFAAOCAgEAncDZNytDbrrVe68UT6py1lfF2h6Tm2p8ro42i87WWyP2LK8YnLHC0hvNfWeWmjZQYBQfGC5c7aQRezak+tHLdmrN" +
            "KHkn5kn+9E9LCjCaEsyIIn2jqdHlAkepu/C3KnNtVx5tW07e5bvIjJScwkCDbP3akWQixPpRFAsnP+ULx7k0aO1xqAeaAhQ2rgo1F58hcflgqKTXnpPM02in" +
            "tVfiVVkX5GXpJjK5EoQtLceyGOrkxlM/sTPq4UrnypmsqSagWV3HcUlYtDinc+nukFk6eR4XkzXBbwKajl0YjztfrCIHOn5QCJL6TERVDbM/aAPly8kJ1sWG" +
            "LuvvWYzMYgLzDul//rUF10gEMWaXVZV51KpS9DY/5CunuvCXmEQJHo7kGcViT7sETn6Jz9KOhvYcXkJ7po6d93A/jy4GKPIPnsKKNEmRxUuXY4xRdh45tMJn" +
            "LTUDdC9FIU0flTeO9/vNpVA8OPU1i14vCz+MU8KX1bV3GXm/fxlB7VBBjX9v5oUep0o/j68R/iDlCOM4VVfRa8gX6T2FU7fNdatvGro7uQzIvWofgN9WUwCb" +
            "EMBy/YhBSrXycKA8crgGg3x1mIsopn88JKwmMBa68oS7EHM9w7C4y71M7DiA+/9Qdp9RBWJpTS9i/mDnJg1xvo8Xz49mrrgfmcAXTCJqXi24NatI3Oc="),
        new(AcmeEnvironment.Staging, CaKeyType.RSA, CaKind.Root, "(STAGING) Yonder Yam Root YR", "(STAGING) Yonder Yam Root YR (self-signed)", "https://letsencrypt.org/certs/staging/gen-y/root-yr.der",
            "MIIFUzCCAzugAwIBAgIRAOlpfXfxOryRKxxm6YaAvS0wDQYJKoZIhvcNAQELBQAwQzELMAkGA1UEBhMCVVMxDTALBgNVBAoTBElTUkcxJTAjBgNVBAMTHChT" +
            "VEFHSU5HKSBZb25kZXIgWWFtIFJvb3QgWVIwHhcNMjUwOTAzMDAwMDAwWhcNNDUwOTAyMjM1OTU5WjBDMQswCQYDVQQGEwJVUzENMAsGA1UEChMESVNSRzEl" +
            "MCMGA1UEAxMcKFNUQUdJTkcpIFlvbmRlciBZYW0gUm9vdCBZUjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALae7+rQafYA6YhlSzozLNXkvQ4C" +
            "LaYBVPUXicG/0soLOqvuhFAsX4uagzipA5XYlTrZY7sABb/OttajOLpGOjpkQSAPYZwrrpyZSjRI0H1gK6sDDqKOYi2eKatFD+IbViZbpDqFaK0qLiv9xNV1" +
            "k0d2cCJiKHwtPqdttN06Q204YYD80/2Y7zFBNuKkEwXELSfMCCe58/5OgfzcjNvhphDDRRddQbW1GplRSVzEYvimXkaCv20EwI3j6WP9AdQw3KoEHMAm97CD" +
            "o+crBVCu6icnGvF5OWxfMBThcRhypkUT6zKW+7V3U1x5UspgwrVMffAgn8Ka/u/r5x4GqrFuWH69wBrfT+Ui/t4XJsMOI9F8egdxOJtBPvIPZrSdS9ZOwmmq" +
            "cIHkVtIIYnSiZjfuYGN6dhuz/B6uMlgvn5ictTlgoOhg8GZgjELvwDFGsEVeNAFGGWWAQHqG2VP7inJm1ilF7mpNW2mVqe6Ko3LCAysWzJIOiho4S21XIR3G" +
            "FLJQqC/gI0oXwAN5/FidHI1N6fgTJFo0ylbgHy2DfwwO+gr30Vl9Ng/q4hs91bBVwsPZOZhRNM5vlYXPMSN01jYVOkJukdSq4AlNqjqYGifEZaJFCt0BVqyH" +
            "TgCEMDtJXnso03fzHr7MOtgc4NK20NZEt4fnlgXAbJDQhSSg7o87RngnAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud" +
            "DgQWBBRQsdeYAlBf2zJGG1jBaEByJG9KwTANBgkqhkiG9w0BAQsFAAOCAgEAb177bev0tqVDJU1pu2Kgpn8007LXfcjfatJTZ4A8TFvgtkf2AyH9Qu3AMuqr" +
            "9pMee7CRVMvA8AhpMhrWTHyzxPyFGlt8t/U+75zq9mE9IWNXMkWWrfph3wcNFDFkrEh6Hfhd1dd8UcqUP6nJAuZYU69NVSQegthqeaZyA6owYDNmCcon4Fc4" +
            "nudmfEyZsdTRXctbhy9QaXKndIyQ2nBWlyNLOgVLLMSHfuk3ksgNO5R68tfhevtR9nBSUORZHQc0Qc2+zBlE7tVhSwtkyfhRa29zQy8XkcjG3EX6pLMgPkJI" +
            "MKhour1mDudeJ3gkfAli9RMSUKdGRnP6/JmSPt1iTnQstG+L5abq1QVLymkxx+gLL5P7sixWo7pXmXnejafYxK8dYgAVYF/wHV/EiIWcxkfUG8pU4SrC/z0Y" +
            "r66C5uovtvpzvcxAjV4YYNLNJg2crbB9WiriBI4b9/L1YTbwPvrxjcoQ8/XQZ1gQIIUJAi7w3ZecOdNWX+S35EiNpjUArCELRPAyYh4gd3WeRS1woH9aIr7q" +
            "EkBWW6IhbLOntrNvrguPprsvf5dlJ93EAVJ8fgOjJTBbl5/tuhxa0IhOwAaSDM3Ep1J8IbzTMgzOofRtrWcTMmtKkaViidQFFCs8jqvB3eBiMnWQdlOhc6f6" +
            "VwbPwd70DybV2JlWelXlLys="),
        new(AcmeEnvironment.Staging, CaKeyType.RSA, CaKind.Root, "(STAGING) Yonder Yam Root YR", "(STAGING) Yonder Yam Root YR (cross-signed by Pretend Pear X1)", "https://letsencrypt.org/certs/staging/gen-y/root-yr-by-x1.der",
            "MIIGEjCCA/qgAwIBAgIQaISp1C1X27jzKrNteMt9pjANBgkqhkiG9w0BAQsFADBmMQswCQYDVQQGEwJVUzEzMDEGA1UEChMqKFNUQUdJTkcpIEludGVybmV0" +
            "IFNlY3VyaXR5IFJlc2VhcmNoIEdyb3VwMSIwIAYDVQQDExkoU1RBR0lORykgUHJldGVuZCBQZWFyIFgxMB4XDTI1MDkwMzAwMDAwMFoXDTMyMDkwMjIzNTk1" +
            "OVowQzELMAkGA1UEBhMCVVMxDTALBgNVBAoTBElTUkcxJTAjBgNVBAMTHChTVEFHSU5HKSBZb25kZXIgWWFtIFJvb3QgWVIwggIiMA0GCSqGSIb3DQEBAQUA" +
            "A4ICDwAwggIKAoICAQC2nu/q0Gn2AOmIZUs6MyzV5L0OAi2mAVT1F4nBv9LKCzqr7oRQLF+LmoM4qQOV2JU62WO7AAW/zrbWozi6Rjo6ZEEgD2GcK66cmUo0" +
            "SNB9YCurAw6ijmItnimrRQ/iG1YmW6Q6hWitKi4r/cTVdZNHdnAiYih8LT6nbbTdOkNtOGGA/NP9mO8xQTbipBMFxC0nzAgnufP+ToH83Izb4aYQw0UXXUG1" +
            "tRqZUUlcxGL4pl5Ggr9tBMCN4+lj/QHUMNyqBBzAJvewg6PnKwVQruonJxrxeTlsXzAU4XEYcqZFE+sylvu1d1NceVLKYMK1TH3wIJ/Cmv7v6+ceBqqxblh+" +
            "vcAa30/lIv7eFybDDiPRfHoHcTibQT7yD2a0nUvWTsJpqnCB5FbSCGJ0omY37mBjenYbs/werjJYL5+YnLU5YKDoYPBmYIxC78AxRrBFXjQBRhllgEB6htlT" +
            "+4pyZtYpRe5qTVtplanuiqNywgMrFsySDooaOEttVyEdxhSyUKgv4CNKF8ADefxYnRyNTen4EyRaNMpW4B8tg38MDvoK99FZfTYP6uIbPdWwVcLD2TmYUTTO" +
            "b5WFzzEjdNY2FTpCbpHUquAJTao6mBonxGWiRQrdAVash04AhDA7SV57KNN38x6+zDrYHODSttDWRLeH55YFwGyQ0IUkoO6PO0Z4JwIDAQABo4HeMIHbMA4G" +
            "A1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRQsdeYAlBf2zJGG1jBaEByJG9KwTAfBgNVHSMEGDAWgBS182Xy/rAKkh/7PH3zRKCs" +
            "YyXDFDA2BggrBgEFBQcBAQQqMCgwJgYIKwYBBQUHMAKGGmh0dHA6Ly9zdGcteDEuaS5sZW5jci5vcmcvMBMGA1UdIAQMMAowCAYGZ4EMAQIBMCsGA1UdHwQk" +
            "MCIwIKAeoByGGmh0dHA6Ly9zdGcteDEuYy5sZW5jci5vcmcvMA0GCSqGSIb3DQEBCwUAA4ICAQCtvBCDHE/cL+eDykgSTAAdsUdGUW7TtMz7fYH3sRDKUx3C" +
            "WGch0GPEnaosOSXJr6gX6GAOiZxZkcr9li/RPnlEJefj1bZaxLf3k57MsBI61Yi9dO/boUwkV2GZaI6gUnwWUrCySIi/Q8LBC7teUhRbCcNRyxgznAUS1Pas" +
            "q2Rrn90QCtNGbMIzkpEsrtyJc7Ivoo4KI74Q9xukFL80abp8/aeZT16nc8I+R4GKDUDbvMGFlzQi03maL2GG4ZdcAGQj5cpJtWLAgRIcYJZoeAiUmYRu/THz" +
            "e0CjrfvT0VD79JQzZ3CZMsE6bcUmOZawpyAcJVbsGCOI3oF52lDG4Hu8FUFRIvBk6WllBe+SoNUL0+sCJyjwLOZtdOta7+LPf70mZx0CT3lu8g0kZ5EpyDsR" +
            "f7XO6IPajaFn98MMjMo5fyejgJfZjE9+ZBJXjhtBEw5wD/YCnLwwNh/uuIY2RvsxzO/wHy4cUm/V5QNGW/NAllKd4Xq3OWs2hfXQxTsPY3WqhRvUBqOCvzIx" +
            "juXdR8GEBkWcb6l/TXxAGdfXcZUWXLe5Y1Tt4XgnW7PVp0qbO/QCBAlQmz6fVrw4mvg2Lq+LNPcx4Z2X8/mvAuaj70zI+6FnuasayJiVYd82ZPqBljt53Q48" +
            "bn3YeS6ipwp3yqmBpNRe/EYeSmucYfahlydOBg=="),
        new(AcmeEnvironment.Staging, CaKeyType.ECDSA, CaKind.Root, "(STAGING) Pretend Pear X1", "(STAGING) Pretend Pear X1", "https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x1.der",
            "MIIFmDCCA4CgAwIBAgIQU9C87nMpOIFKYpfvOHFHFDANBgkqhkiG9w0BAQsFADBmMQswCQYDVQQGEwJVUzEzMDEGA1UEChMqKFNUQUdJTkcpIEludGVybmV0" +
            "IFNlY3VyaXR5IFJlc2VhcmNoIEdyb3VwMSIwIAYDVQQDExkoU1RBR0lORykgUHJldGVuZCBQZWFyIFgxMB4XDTE1MDYwNDExMDQzOFoXDTM1MDYwNDExMDQz" +
            "OFowZjELMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1cml0eSBSZXNlYXJjaCBHcm91cDEiMCAGA1UEAxMZKFNUQUdJTkcp" +
            "IFByZXRlbmQgUGVhciBYMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALbagEdDTa1QgGBWSYkyMhscZXENOBaVRTMX1hceJENgsL0Ma49D3Mil" +
            "I4KS38mtkmdF6cPWnL++fgehT0FbRHZgjOEr8UAN4jH6omjrbTD++VZneTsMVaGamQmDdFl5g1gYaigkkmx8OiCO68a4QXg4wSyn6iDipKP8utsE+x1E28SA" +
            "75HOYqpdrk4HGxuULvlr03wZGTIf/oRt2/c+dYmDoaJhge+GOrLAEQByO7+8+vzOwpNAPEx6LW+crEEZ7eBXih6VP19sTGy3yfqK5tPtTdXXCOQMKAp+gCj/" +
            "VByhmIr+0iNDC540gtvV303WpcbwnkkLYC0Ft2cYUyHtkstOfRcRO+K2cZozoSwVPyB8/J9RpcRK3jgnX9lujfwA/pAbP0J2UPQFxmWFRQnFjaq6rkqbNEBg" +
            "Ly+kFL1NEsRbvFbKrRi5bYy2lNms2NJPZvdNQbT/2dBZKmJqxHkxCuOQFjhJQNeO+Njm1Z1iATS/3rts2yZlqXKsxQUzN6vNbD8KnXRMEeOXUYvbV4lqfCf8" +
            "mS14WEbSiMy87GB5S9ucSV1XUrlTG5UGcMSZOBcEUpisRPEmQWUOTWIoDQ5FOia/GI+Ki523r2ruEmbmG37EBSBXdxIdndqrjy+QVAmCebyDx9eVEGOIpn26" +
            "bW5LKerumJxa/CFBaKi4bRvmdJRLAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBS182Xy/rAKkh/7PH3zRKCs" +
            "YyXDFDANBgkqhkiG9w0BAQsFAAOCAgEAncDZNytDbrrVe68UT6py1lfF2h6Tm2p8ro42i87WWyP2LK8YnLHC0hvNfWeWmjZQYBQfGC5c7aQRezak+tHLdmrN" +
            "KHkn5kn+9E9LCjCaEsyIIn2jqdHlAkepu/C3KnNtVx5tW07e5bvIjJScwkCDbP3akWQixPpRFAsnP+ULx7k0aO1xqAeaAhQ2rgo1F58hcflgqKTXnpPM02in" +
            "tVfiVVkX5GXpJjK5EoQtLceyGOrkxlM/sTPq4UrnypmsqSagWV3HcUlYtDinc+nukFk6eR4XkzXBbwKajl0YjztfrCIHOn5QCJL6TERVDbM/aAPly8kJ1sWG" +
            "LuvvWYzMYgLzDul//rUF10gEMWaXVZV51KpS9DY/5CunuvCXmEQJHo7kGcViT7sETn6Jz9KOhvYcXkJ7po6d93A/jy4GKPIPnsKKNEmRxUuXY4xRdh45tMJn" +
            "LTUDdC9FIU0flTeO9/vNpVA8OPU1i14vCz+MU8KX1bV3GXm/fxlB7VBBjX9v5oUep0o/j68R/iDlCOM4VVfRa8gX6T2FU7fNdatvGro7uQzIvWofgN9WUwCb" +
            "EMBy/YhBSrXycKA8crgGg3x1mIsopn88JKwmMBa68oS7EHM9w7C4y71M7DiA+/9Qdp9RBWJpTS9i/mDnJg1xvo8Xz49mrrgfmcAXTCJqXi24NatI3Oc="),
        new(AcmeEnvironment.Staging, CaKeyType.ECDSA, CaKind.Root, "(STAGING) Bogus Broccoli X2", "(STAGING) Bogus Broccoli X2 (self-signed)", "https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x2.der",
            "MIICTjCCAdSgAwIBAgIRAIPgc3k5LlLVLtUUvs4K/QcwCgYIKoZIzj0EAwMwaDELMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBT" +
            "ZWN1cml0eSBSZXNlYXJjaCBHcm91cDEkMCIGA1UEAxMbKFNUQUdJTkcpIEJvZ3VzIEJyb2Njb2xpIFgyMB4XDTIwMDkwNDAwMDAwMFoXDTQwMDkxNzE2MDAw" +
            "MFowaDELMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1cml0eSBSZXNlYXJjaCBHcm91cDEkMCIGA1UEAxMbKFNUQUdJTkcp" +
            "IEJvZ3VzIEJyb2Njb2xpIFgyMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEOvS+w1kCzAxYOJbA06Aw0HFP2tLBLKPoFQqR9AMskl1nC2975eQqycR+ACvYelA8" +
            "rfwFXObMHYXJ23XLB+dAjPJVOJ2OcsjTVqO4dcDWu+rQ2VILdnJRYypnV1MMThVxo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNV" +
            "HQ4EFgQU3tGjWWQOwZo2o0busBB2766XlWYwCgYIKoZIzj0EAwMDaAAwZQIwRcp4ZKBsq9XkUuN8wfX+GEbY1N5nmCRc8e80kUkuAefouc2j3cICeXo1cOyb" +
            "Q1iWAjEA3Ooawl8eQyR4wrjCofUE8h44p0j7Yl/kBlJZT8+9vbtH7QiVzeKCOTQPINyRql6P"),
        new(AcmeEnvironment.Staging, CaKeyType.ECDSA, CaKind.Root, "(STAGING) Bogus Broccoli X2", "(STAGING) Bogus Broccoli X2 (cross-signed by Pretend Pear X1)", "https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x2-signed-by-x1.der",
            "MIIEmTCCAoGgAwIBAgIRAJJVIr2Em/sOzhBD2bEnEJwwDQYJKoZIhvcNAQELBQAwZjELMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5l" +
            "dCBTZWN1cml0eSBSZXNlYXJjaCBHcm91cDEiMCAGA1UEAxMZKFNUQUdJTkcpIFByZXRlbmQgUGVhciBYMTAeFw0yMDA5MDQwMDAwMDBaFw0yNTA5MTUxNjAw" +
            "MDBaMGgxCzAJBgNVBAYTAlVTMTMwMQYDVQQKEyooU1RBR0lORykgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxJDAiBgNVBAMTGyhTVEFHSU5H" +
            "KSBCb2d1cyBCcm9jY29saSBYMjB2MBAGByqGSM49AgEGBSuBBAAiA2IABDr0vsNZAswMWDiWwNOgMNBxT9rSwSyj6BUKkfQDLJJdZwtve+XkKsnEfgAr2HpQ" +
            "PK38BVzmzB2Fydt1ywfnQIzyVTidjnLI01ajuHXA1rvq0NlSC3ZyUWMqZ1dTDE4VcaOB7TCB6jAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAd" +
            "BgNVHQ4EFgQU3tGjWWQOwZo2o0busBB2766XlWYwHwYDVR0jBBgwFoAUtfNl8v6wCpIf+zx980SgrGMlwxQwNgYIKwYBBQUHAQEEKjAoMCYGCCsGAQUFBzAC" +
            "hhpodHRwOi8vc3RnLXgxLmkubGVuY3Iub3JnLzArBgNVHR8EJDAiMCCgHqAchhpodHRwOi8vc3RnLXgxLmMubGVuY3Iub3JnLzAiBgNVHSAEGzAZMAgGBmeB" +
            "DAECATANBgsrBgEEAYLfEwEBATANBgkqhkiG9w0BAQsFAAOCAgEAMkp5etLOxM4+a6EqX2hmAd+yNUSNCA7+MYn/VrwJnpkWe8zuC+fILYMYRuByWs/zeFmo" +
            "56Jc7td5N9I+QN0rYSeEbgdTAMeaBjZ3P6eJxM1Aa76Abrj5ULfq8XhOE37SYgFbZS9YPOQ4wuisCXHrrmu4ZdZJmzXIQX562xBeJxf0o4LBqS2C3SmpkPY+" +
            "f8lTtmFO/I6qSSl8T5XyNE385zNXaRd8rMJqNC9fIHDjPeJMIaou0TZYT0uNb9OZ7ZhT7smQSaHcGxtK0SVmJvGNagc6RldrHFbemLbwVpeI4NopRHynQqzk" +
            "VtsfAlK8VD92SYbpolFsJZWuHVkHgccuI1Hx0+RUp1VGj1PPV+0JmGZeG2ybLloU2rjjMbRmkNjTxub2U1vzCGpBSaBfYQLjLHDwQk1AqRENlZxDqCkXFro8" +
            "eqT6TFHdtw27KIT+ov1Qyofiq3Uj1w7tPpcFMSDfiWNRE0XGYCjELDo19oPqQthIMQ5X+/3YpCqZceR4vMR6n9olLp/0KmjAzqU+LqD2fmFLttKvZUxW8aEC" +
            "TGIcDHGCPJDklwDW3l7DUQ08Wj5Fh/KEf5c9fF3u87WUAJu4Vh9C+ewXZtzL0LD46lYgpn7fv5w9sLS4zQ3CIC3udjJ5Gc/v8VhPQaU1Enn7NW+4IHnfSeP6" +
            "G5rzLEtl0PreC4k="),
        new(AcmeEnvironment.Staging, CaKeyType.ECDSA, CaKind.Root, "(STAGING) Yearning Yucca Root YE", "(STAGING) Yearning Yucca Root YE (self-signed)", "https://letsencrypt.org/certs/staging/gen-y/root-ye.der",
            "MIICDDCCAZKgAwIBAgIRAJacQQzEKTdLO8Jbc8CHVlQwCgYIKoZIzj0EAwMwRzELMAkGA1UEBhMCVVMxDTALBgNVBAoTBElTUkcxKTAnBgNVBAMTIChTVEFH" +
            "SU5HKSBZZWFybmluZyBZdWNjYSBSb290IFlFMB4XDTI1MDkwMzAwMDAwMFoXDTQ1MDkwMjIzNTk1OVowRzELMAkGA1UEBhMCVVMxDTALBgNVBAoTBElTUkcx" +
            "KTAnBgNVBAMTIChTVEFHSU5HKSBZZWFybmluZyBZdWNjYSBSb290IFlFMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE9LGxyXLRIUhNaCaufjztgLQYSwTDaqNh" +
            "kD9nrf3IOkM1o5hqKUTGOm3SuJVqzzLrRXT7JL+UCtshYPi5VSbyaH8JXgogE+HlzMPK/jQEsjYo91J9mEjnl1RQyhMyI3wlo0IwQDAOBgNVHQ8BAf8EBAMC" +
            "AQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkzsblChigfkfJ+uq35owDVquf+wwCgYIKoZIzj0EAwMDaAAwZQIwDlg5ZRknz/QOduNyg84Dy3oZwsMw" +
            "0I0R180ZBzQ6YVNZZVbmyirNg3NJ3NP/kkS5AjEA24b8Va6T6LmSXZqAJjnQjL71IZ20L6Nt7/g98v9hPxd+jq4hSuGvm85jKQNZdK65"),
        new(AcmeEnvironment.Staging, CaKeyType.ECDSA, CaKind.Root, "(STAGING) Yearning Yucca Root YE", "(STAGING) Yearning Yucca Root YE (cross-signed by Bogus Broccoli X2)", "https://letsencrypt.org/certs/staging/gen-y/root-ye-by-x2.der",
            "MIICyDCCAk+gAwIBAgIQSgI+xtsh896Dpo5WNwhksDAKBggqhkjOPQQDAzBoMQswCQYDVQQGEwJVUzEzMDEGA1UEChMqKFNUQUdJTkcpIEludGVybmV0IFNl" +
            "Y3VyaXR5IFJlc2VhcmNoIEdyb3VwMSQwIgYDVQQDExsoU1RBR0lORykgQm9ndXMgQnJvY2NvbGkgWDIwHhcNMjUwOTAzMDAwMDAwWhcNMzIwOTAyMjM1OTU5" +
            "WjBHMQswCQYDVQQGEwJVUzENMAsGA1UEChMESVNSRzEpMCcGA1UEAxMgKFNUQUdJTkcpIFllYXJuaW5nIFl1Y2NhIFJvb3QgWUUwdjAQBgcqhkjOPQIBBgUr" +
            "gQQAIgNiAAT0sbHJctEhSE1oJq5+PO2AtBhLBMNqo2GQP2et/cg6QzWjmGopRMY6bdK4lWrPMutFdPskv5QK2yFg+LlVJvJofwleCiAT4eXMw8r+NASyNij3" +
            "Un2YSOeXVFDKEzIjfCWjgd4wgdswDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFJM7G5QoYoH5Hyfrqt+aMA1arn/sMB8GA1Ud" +
            "IwQYMBaAFN7Ro1lkDsGaNqNG7rAQdu+ul5VmMDYGCCsGAQUFBwEBBCowKDAmBggrBgEFBQcwAoYaaHR0cDovL3N0Zy14Mi5pLmxlbmNyLm9yZy8wEwYDVR0g" +
            "BAwwCjAIBgZngQwBAgEwKwYDVR0fBCQwIjAgoB6gHIYaaHR0cDovL3N0Zy14Mi5jLmxlbmNyLm9yZy8wCgYIKoZIzj0EAwMDZwAwZAIweTPoduxM5YwBYzKb" +
            "kR/+0lQUnA0HFZd0iH1XXUsxrIBczAWM49uSj4q9EeY4ZhKCAjA5Vddt2uTF6hFeJhVIm0QeevLJeiPjawJ/3EDRjVKdy6lzcSqgD4v51KLIYwfUL4M="),
    ];
}
