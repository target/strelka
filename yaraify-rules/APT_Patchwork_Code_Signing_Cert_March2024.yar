
import "pe"

rule APT_Patchwork_Code_Signing_Cert_March2024 {
    meta:
        Description = "Detects malware used by Indian APT Patchwork based on the Code Signing Certificate"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://twitter.com/malwrhunterteam/status/1771152296933531982"
        Credits = "@malwrhunterteam for sharing the resuse of the certificate and references. @__0XYC__ and @ginkgo_g for sharing the malware hashes and attribution to APT"
        File_Hash = "8f4cf379ee2bef6b60fec792d36895dce3929bf26d0533fbb1fdb41988df7301"
        date = "2024-03-29"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "4f8bd643c59658e3d5b04d760073cbe9"
        yarahub_uuid = "1c970867-5a51-4243-9f0a-db802f28cc12"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    condition:
        for any signature in pe.signatures:
            (signature.thumbprint == "424ef52be7acac19da5b8203494959a30b818f8d"
            or signature.issuer contains "CN=RUNSWITHSCISSORS LTD")
 }











