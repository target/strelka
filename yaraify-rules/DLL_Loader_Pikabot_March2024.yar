import "pe"

rule DLL_Loader_Pikabot_March2024 {
    meta:
        Description = "Detects Pikabot Loader malware based on PE import & export properties"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Credits = "@pr0xylife for sharing the malware sample"
        Reference = "https://bazaar.abuse.ch/sample/238dcc5611ed9066b63d2d0109c9b623f54f8d7b61d5f9de59694cfc60a4e646/"
        Hash = "238dcc5611ed9066b63d2d0109c9b623f54f8d7b61d5f9de59694cfc60a4e646"
        date = "2024-03-09"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "4b1518535af6344af39bd90aa02a6c0d"
        yarahub_uuid = "ccf63b52-a6e4-40ff-928d-5ac63b89a15d"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.pikabot"

    condition:
        pe.imphash() == "55f1ba0b782341fa929d61651ef47f0c"
        and for 7 export in pe.export_details:
        (export.name startswith "Tmph")
        and pe.exports("HetModuleProp")
        and pe.exports("GetModul")
}