import "pe"

rule EXE_Stealer_Elusive_Feb2024 {
    meta:
        Description = "Detects Elusive Stealer malware"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Credits = "Yogesh Londhe for sharing the malware sample hash"
        Reference = "https://twitter.com/suyog41/status/1760168286711677328"
        Hash = "7bd84d2f0ac282b9351f5243f5ad4c85b7bd6081fcf8887a89d33f0ba7422eeb"
        date = "2024-02-26"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "0f00b9d4f63ec99dc4bb6dd729811e9a"
        yarahub_uuid = "bb7f04d5-ed51-442c-a147-3062a66e6821"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
       
    strings:
        $geo1 = "country_flag"
        $geo2 = "country_capital"
        $geo3 = "country_phone"
        $geo4 = "continent_code"
        $geo5 = "timezone_name"
        $geo6 = "currency_code"
        
        $wal1 = "Wallets/Armory Wallet/"
        $wal2 = "Wallets/Bitcoin Core/"
        $wal3 = "Wallets/Exodus/"
        $wal4 = "Wallets/Coinomi/wallets/"
        $wal5 = "Wallets/Litecoin/"
        $wal6 = "Wallets/DashCore/"
        $wal7 = "Bitcoin\\wallets"
        $wal8 = "Wallets/Electrum/wallets/"
        $wal9 = "Wallets/Bytecoin/blockchain/"

        $fund1 = "Wallets found -"
        $fund2 = "Apps / Gaming found -"
        $fund3 = "Utilities found -"
        $fund4 = "Credit cards found -"
        $fund5 = "Passwords found -"
        $fund6 = "Autofills found -"
        $fund7 = "Downloads found -"
        $fund8 = "History found -"

    condition:
        pe.pdb_path == "C:\\ooo999\\TG\\x64\\Release\\x64.pdb"
        or pe.imphash() == "1b0344949f65b67c032e1179ce6311b7"
        or (
            3 of ($geo*)
            and 5 of ($wal*)
            and 5 of ($fund*)
        )
     
 }


 