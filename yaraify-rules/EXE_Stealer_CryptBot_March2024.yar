import "pe"

rule EXE_Stealer_CryptBot_March2024 {
    meta:
        Description = "Detects a new version of CryptBot Stealer"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Credits = "@RussianPanda9xx for identifying the new version of the malware"
        Reference = "https://twitter.com/RussianPanda9xx/status/1766163567873593476"
        Hash = "490625afa4de3eac3b03d1ca3e81afab07b5e748423319ee6e08f58c40d20250"
        date = "2024-03-08"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "1a7e222ee2b63b43c8c7b497a5b0f252"
        yarahub_uuid = "9658768f-cc83-417f-b18d-ed3cfba1570c"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.cryptbot"

    condition:
        pe.imphash() == "48d4a6a3111a18b082fa3638b1568f64"
        and pe.number_of_sections == 8
        and pe.number_of_resources == 6
        and for 4 resource in pe.resources:
        (resource.type == pe.RESOURCE_TYPE_ICON)
}