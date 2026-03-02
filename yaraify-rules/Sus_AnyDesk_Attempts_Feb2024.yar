import "pe"

rule Sus_AnyDesk_Attempts_Feb2024 {
    meta:
        Description = "Detects files attempting to impersonate AnyDesk Windows Version"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Credits = "Inspired by Florian Roth"
        Reference = "https://twitter.com/cyb3rops/status/1753440743480238459"
        Goodware_Hash = "55e4ce3fe726043070ecd7de5a74b2459ea8bed19ef2a36ce7884b2ab0863047"
        date = "2024-02-03"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "a21768190f3b9feae33aaef660cb7a83"
        yarahub_uuid = "b56ea799-6bae-4fd8-bc1a-362fc4c3aaf4"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    
    condition:
       pe.version_info["CompanyName"] contains  "AnyDesk"
       and pe.version_info["LegalCopyright"] != "(C) 2022 AnyDesk Software GmbH"
       and pe.pdb_path != "C:\\Users\\anyadmin\\Documents\\anydesk\\release\\app-32\\win_loader\\AnyDesk.pdb"
    
 }

 