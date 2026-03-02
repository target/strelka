import "pe"

rule DLL_Stealer_Ov3rStealer_Feb2024 {
    meta:
        Description = "Detects Ov3r Stealer spread through FaceBook Ads"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://www.trustwave.com/hubfs/Web/Library/Documents_pdf/FaceBook_Ad_Spreads_Novel_Malware.pdf"
        Hash = "c6765d92e540af845b3cbc4caa4f9e9d00d5003a36c9cb548ea79bb14c7e8f66"
        date = "2024-02-09"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "b042b2a8981a94b7afe680d94808e9f8"
        yarahub_uuid = "ed7cc2b0-456f-4f74-8244-9b53fc216812"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.phemedrone_stealer"
        
    condition:
        pe.dll_name == "Dropper.dll"
        and pe.number_of_exports > 125
        and for 100 export in pe.export_details:
        (export.name startswith "Wer")
       
 }