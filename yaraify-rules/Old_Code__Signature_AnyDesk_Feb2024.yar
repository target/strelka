import "pe"

rule Old_Code__Signature_AnyDesk_Feb2024 {
    meta:
        Description = "Detects files with older and no longer valid code signing certifcates of AnyDesk"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Credits = "Inspired by Florian Roth"
        Reference = "https://twitter.com/cyb3rops/status/1753440743480238459"
        Goodware_Hash = "55e4ce3fe726043070ecd7de5a74b2459ea8bed19ef2a36ce7884b2ab0863047"
        date = "2024-02-03"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "a21768190f3b9feae33aaef660cb7a83"
        yarahub_uuid = "fa45b9a9-0db8-4b3a-b60e-f6eb7bc01f0f"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    
    condition:
        pe.version_info["CompanyName"] contains "AnyDesk"
        and for 2 signature in pe.signatures:
        (signature.thumbprint != "646f52926e01221c981490c8107c2f771679743a") //Latest AnyDesk Code Sign Cert
       
 }

 