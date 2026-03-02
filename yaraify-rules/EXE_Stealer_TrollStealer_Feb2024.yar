import "pe"

rule EXE_Stealer_TrollStealer_Feb2024 {
    meta:
        Description = "Detects Troll Stealer malware used by Kimsuky based on the PE export properties"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://medium.com/s2wblog/kimsuky-disguised-as-a-korean-company-signed-with-a-valid-certificate-to-distribute-troll-stealer-cfa5d54314e2"
        Hash = "61b8fbea8c0dfa337eb7ff978124ddf496d0c5f29bcb5672f3bd3d6bf832ac92"
        date = "2024-02-11"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "88f183304b99c897aacfa321d58e1840"
        yarahub_uuid = "2a5a1a3e-e758-4de6-976c-f306b47d4f3f"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.troll_stealer"

    condition:
        pe.signatures[0].subject contains "D2innovation"
        and pe.signatures[0].serial == "00:88:90:ca:b1:cd:51:0c:d2:0d:ab:4c:e5:94:8c:bc:3a"
        and pe.dll_name == "golang.dll"
        and pe.export_details[0].name == "_cgo_dummy_export" 
        and for 9 export in pe.export_details:
        (export.name endswith "Trampoline")
       
 }
