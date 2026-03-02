import "pe"

rule EXE_Stealer_WhiteSnake_Jan2024 {
    meta:
        Description = "Detects White Snake Stealer samples based on network strings and dotnet resources"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://bazaar.abuse.ch/browse/signature/WhiteSnakeStealer/"
        Hash = "cc9e5bfeb86b7fe80b33a4004eb0912820f09dec29a426a8a4136f7306c08d04"
        date = "2024-01-29"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "b00bd190f37328c060a0446e6414de72"
        yarahub_uuid = "08ae261a-4c32-4ff4-b387-4fa3e62d58e6"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.whitesnake"

    strings: 
        $net1 = "get_beaconService" 
        $net2 = "set_beaconService" 
        $net3 = "get_HttpMethod" 
        $net4 = "HttpListenerRequest" 
        $net5 = "HttpListenerContext" 
        $net6 = "DownloadData" 
        $net7 = "UploadData" 
        $net8 = "WebClient" 
        $net9 = "TcpClient" 
        $s = "_HELLO_BITCH"

    condition:
       uint16(0) == 0x5a4d
       and 5 of ($net*)
       and #s > 10
       and pe.imports("mscoree.dll","_CorExeMain") // Written in .Net
       
 }
