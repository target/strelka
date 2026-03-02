import "pe"

rule EXE_Ransomware_Phobos_Feb2024 {
    meta:
        Description = "Detects Phobos Ransomware that was used to attack hospitals in Romania"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Credits = "Is Now on VT! for the notification of the malware sample"
        Reference = "https://grahamcluley.com/20-hospitals-in-romania-hit-hard-by-ransomware-attack-on-it-service-provider/"
        Hash = "396a2f2dd09c936e93d250e8467ac7a9c0a923ea7f9a395e63c375b877a399a6"
        Sample_Size = "Matches around 125 Phobos Samples"
        date = "2024-02-21"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "ca52ef8f80a99a01e97dc8cf7d3f5487"
        yarahub_uuid = "be73dd7a-acee-4a8d-a57f-a1dbd18482ba"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.phobos"
    
    strings:
        $hex = {5c005c003f005c0055004e0043005c005c005c0065002d00}  // Represents \\?\UNC\\\e-
    condition:
        pe.imphash() == "851a0ba8fbb71710075bdfe6dcef92eb"
        and $hex
       
 }
