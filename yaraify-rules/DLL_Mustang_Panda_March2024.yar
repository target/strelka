import "pe"

rule DLL_Mustang_Panda_March2024 {
    meta:
        Description = "Detects a malicious DLL used by Mustang Panda (aka TA416) in a New Year Themed Campaign"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Credits = "@smica83 for sharing the malware sample on Malware Bazaar"
        Reference = "https://cyble.com/blog/festive-facade-dissecting-multi-stage-malware-in-new-year-themed-lure/"
        Hash = "dd261a5db199b32414c33136aed44c3ebe2ae55f18991ae3dc341fc43a1ef7f4"
        date = "2024-03-10"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "7ea17ffb336a7d8b24d62ba78151d264"
        yarahub_uuid = "4212deb2-8075-4756-a881-c7bf1296bd37"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $unrefdll = "mscoree.dll"
    condition:
        pe.number_of_signatures == 0
        and pe.imphash() == "ff98d730c7b4fbaa92b85279e37acb21"
        and for 3 export in pe.export_details:
        (export.name startswith "WMGet")
        and pe.exports("DMGetDesktopInfo")
        and pe.exports("NVAutoStart")
        and pe.exports("NVLoadDatabase")
        and pe.exports("PMEnum")
        and any of them

}