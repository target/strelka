import "pe"

rule EXE_Stealer_Nightingale_Imphash_Jan2024 {
    meta:
        Description = "Detects Nightingale Stealer samples based on the import hash"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Credits = "Yogesh Londhe @suyog41 for sharing the File Hash on Twitter"
        Reference = "https://twitter.com/suyog41/status/1751930165230469619"
        Hash = "0c0cc6d724ac017163b40866c820fd67df6ac89924a623490ec1de2ecacf1d0219"
        date = "2024-01-30"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "a1d8eceb8c701feb83b225d73fc237be"
        yarahub_uuid = "140a3497-8aa0-4bc3-9a5c-5d9825126394"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    condition:
       pe.imphash() == "b92e25fdf67d41fe9a0f94a46fd5528a"
       
 }
