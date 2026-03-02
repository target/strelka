import "pe"

rule EXE_Loader_WikiLoader_Feb2024 {
    meta:
        Description = "Detects Wiki Loader samples based on PE import & export properties"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Credits = "Thanks to pr0xylife and Mangusta for uploading the samples"
        Reference = "https://bazaar.abuse.ch/browse/signature/WikiLoader/"
        Hash = "0de42118dd0cd861bea13de097457ccb407aae901b14e0bec59b0abe660cdf1f"
        date = "2024-02-07"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "9a0d92c54d88bd609899fc03b0511df4"
        yarahub_uuid = "4e535277-dfa6-4a33-83c7-18f36fa38aea"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.wikiloader"
    
    condition:
        pe.number_of_signatures == 1
        and pe.version_info["LegalCopyright"] == "Copyright 2019 by Don HO"
        and pe.imphash() == "e907b96b3a2773e8cd582e4019534188"
        or (pe.imports("KERNEL32.dll","GetStartupInfoW")
            and pe.imports("KERNEL32.dll","GetOEMCP")
            and pe.imports("USER32.dll", "GetClientRect")
            and pe.imports("USER32.dll", "ClientToScreen"))
        and pe.dll_name == "mimeTools.dll"
        and for 2 export in pe.export_details:
        (export.name == "beNotified" 
        or export.name == "setInfo" 
        or export.name == "getName")
       
 }

//---------------------------NOTE----------------------------------
//Without the pe.dll_name, this rule matched on two other file hashes from 2022:
//e1ecf0f7bd90553baaa83dcdc177e1d2b20d6ee5520f5d9b44cdf59389432b10  ZINC weaponizing open-source software
//a881c9f40c1a5be3919cafb2ebe2bb5b19e29f0f7b28186ee1f4b554d692e776  Following the Lazarus group by tracking DeathNote campaign

