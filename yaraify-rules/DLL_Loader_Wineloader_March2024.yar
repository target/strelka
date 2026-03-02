import "pe"

rule DLL_Loader_Wineloader_March2024 {
    meta:
        Description = "Detects Wineloader malware used by the SpikedWine Threat Actor in campaigns against European Diplomats"
        Author = "RustyNoob619"
        Reference = "https://www.zscaler.com/blogs/security-research/european-diplomats-targeted-spikedwine-wineloader"
        Hash = "72b92683052e0c813890caf7b4f8bfd331a8b2afc324dd545d46138f677178c4"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        date = "2024-03-01"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "7961263963841010a049265956b14666"
        yarahub_uuid = "c53632a3-01b0-4842-b83e-05857dc38380"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.wineloader"

    strings:
        $RC4 = {16 6f 18 23 34 fb 55 ad cc af db 7b 96 01 dc ff 4f e0 57 72 fb 37 a4 0f 83 26 2d 13 61 d5 b9 13 5c 18
                f2 a8 4b 77 27 b8 4e bf 7c 59 8b bf e2 be 94 ff 71 60 33 28 44 4a 67 63 2b ac e2 f8 09 e8 f0 26 84 d5 a6 7b 8e
                ba be 38 8c ab 43 6c 2f 1f 36 ee e7 cf 7e 0f b7 33 e2 34 6d 01 11 e3 57 65 75 4b 39 d6 bf bd 3e 3f 50 7b e9 9e
                cf bd c8 22 ec 81 98 2d 60 7c bf 0c 5c c2 9a 87 40 ec d5 68 16 04 41 95 d3 df a3 b1 b3 3c ea ef 7e c3 12 c1 0c
                b5 f6 cf 0e 4c 07 f0 79 c8 7d 13 e4 4f 0f e1 d2 7b d0 65 c5 55 5a 3d 56 67 63 49 6d 87 e2 ed 59 57 4d c1 4b f6
                60 8a 3b b9 e3 c0 57 2a e9 23 82 ac 73 00 d8 5f 2b af 38 cb 00 dd fe 0f 88 db d4 a1 07 21 4b c8 7f dd 89 bd 51
                bd 4d 09 30 9b 1f 4d 88 68 0f d1 d7 da 70 1f b5 4d 68 b2 0f 7e b3 0e 92 4a af a5 a2 ac fd 16 26 87 b0 7c 60 4c}

    condition:
        pe.imphash() == "7f07fd94e5bb907093556781cc464017"
        and for 5 export in pe.export_details:
        (export.name == "_set_se_translator" 
        or export.name == "_set_purecall_handler" 
        or export.name == "set_unexpected"
        or export.name == "__telemetry_main_invoke_trigger"
        or export.name == "__telemetry_main_return_trigger")
        and $RC4
       
 }
 




 

 