import "pe"

rule DLL_Unknown_China_Feb2024 {
    meta:
        Description = "Detects an unknown suspicious DLL with Chinise artifacts that appears to impersonate Easy Language Program"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://bazaar.abuse.ch/sample/58d851d4909cd3833f18aec033c8856dc14c5ba60e037114193b92c18e9670b8/"
        Hash = "58d851d4909cd3833f18aec033c8856dc14c5ba60e037114193b92c18e9670b8"
        date = "2024-02-26"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "98f17c5cde1f1a0c9e4d63027d801d6d"
        yarahub_uuid = "357c2647-9d42-4a9c-be41-6acc7749090b"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    condition:
        pe.imphash() == "736bc598358bfd2d88645399ceb66351"
        and pe.export_details[0].name == "HelpCF"
        and pe.resources[0].language == 2052
        and pe.version_info["LegalCopyright"] == "\\\x05HC@\x09 \xf7\x0a\xcdv\x7f(cH"    // (In Chinese) All rights reserved by the author. Please respect and use genuine copies. 
                                                                                       
 }