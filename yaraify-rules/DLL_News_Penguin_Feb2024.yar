
import "pe"

rule DLL_News_Penguin_Feb2024 {
    meta:
        Description = "Detects a DLL that was part of the tooling used by News Penguin to target orgs in Pakistan"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Credits = "Is Now on VT! for notification of the malware sample"
        Reference = "https://blogs.blackberry.com/en/2023/02/newspenguin-a-previously-unknown-threat-actor-targets-pakistan-with-advanced-espionage-tool"
        Hash = "3eecb083d138fdcb5642cd2f0ed00ae6533eb44508e224f198961449d944dd14"
        date = "2024-02-27"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "6dfa9980dfab53220b893d360e36e09b"
        yarahub_uuid = "76ca2873-d81d-475e-9928-50568e8d1802"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    condition:
        pe.imphash() == "e0802b7e9a99fdbe21c766f49a999b72"
        and for all export in pe.export_details:
            (export.name startswith "curl_easy_")        
     
 }

 

 