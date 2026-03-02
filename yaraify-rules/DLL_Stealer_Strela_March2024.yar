
import "pe"

rule DLL_Stealer_Strela_March2024 {
    meta:
        Description = "Detects Strela Stealer malware used in a Large-Scale Campaign in Early 2024"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://unit42.paloaltonetworks.com/strelastealer-campaign/"
        File_Hash = "e6991b12e86629b38e178fef129dfda1d454391ffbb236703f8c026d6d55b9a1"
        date = "2024-03-25"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "9499f14143b34ea7703c73b5f9b37013"
        yarahub_uuid = "8e53b6d5-f673-4d8e-8a19-86f3077f48f1"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.strelastealer"

    condition:
        pe.imphash() == "c21fd41af2cf2392ca8ea5044cf42f43"
        and pe.exports("m")
        and filesize < 10MB
 }













