import "pe"

rule EXE_Stealer_44Caliber_Feb2024 {
    meta:
        Description = "Detects 44 Caliber Stealer malware based on strings"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Credits = "Yogesh Londhe (@suyog41) for identifying and sharing the malware sample"
        Reference = "https://twitter.com/suyog41/status/1762745899946790941"
        Hash = "aa4b851898ca945e0970296800f0273ed170da6349d370fc450412a40497ceff"
        sample_size = "matches over 750 samples in Virus Total"
        date = "2024-02-29"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "bb52051b05b6b1ccccc83df14f66df33"
        yarahub_uuid = "b465fad3-6d74-471e-bb63-36d2de2dd6d2"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    condition:
        pe.imphash() == "2e5467cba76f44a088d39f78c5e807b6"
        and pe.version_info["LegalCopyright"] == "FuckTheSystem Copyright \xa9  2021"
        and pe.version_info["ProductName"] == "44 CALIBER"
        and pe.version_info["FileDescription"] == "44 CALIBER"
        and pe.version_info["Comments"] == "44 CALIBER"
       
 }




 

 