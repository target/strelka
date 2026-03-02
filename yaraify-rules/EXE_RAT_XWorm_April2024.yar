import "pe"

rule EXE_RAT_XWorm_April2024 {
    meta:
        Description = "Detects XWorm RAT malware based on the matched strings"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Credits = "@ShanHolo for the discovery of Open Dir serving XWorm RAT and for sharing the malware hash"
        Reference = "https://twitter.com/ShanHolo/status/1776550052871242089"
        File_Hash = "e761f2d9049734373c12c97aa557183081403e792b40028c410e4a6c0646c2b8"
        date = "2024-04-06"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "6b438a52d60887a534e6e38f72ededff"
        yarahub_uuid = "dfd44930-7deb-4458-ab22-7a6f122e2589"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.xworm"

    strings:
        $wide1 = "\\Log.tmp" wide fullword 
        $wide2 = "WScript.Shell" wide fullword 
        $wide3 = "\\root\\SecurityCenter2" wide fullword 

        $select1 = "Select * from Win32_ComputerSystem" wide fullword 
        $select2 = "Select * from AntivirusProduct" wide fullword 
        $select3 = "SELECT * FROM Win32_VideoController" wide fullword 

        $pwrshll1 = "-ExecutionPolicy Bypass Add-MpPreference -ExclusionPath '" wide
        $pwrshll2 = "-ExecutionPolicy Bypass Add-MpPreference -ExclusionProcess '" wide
        $pwrshll3 = "-ExecutionPolicy Bypass -File \"" wide fullword 

        $antivm1 = "VIRTUAL" wide fullword 
        $antivm2 = "vmware" wide fullword 
        $antivm3 = "VirtualBox" wide fullword 

        $shtdwn1 = "shutdown.exe /f /s /t 0" wide fullword 
        $shtdwn2 = "shutdown.exe /f /r /t 0" wide fullword 
        $shtdwn3 = "shutdown.exe -L" wide fullword

        $cmd1 = "PCShutdown" wide fullword 
        $cmd2 = "PCRestart" wide fullword 
        $cmd3 = "PCLogoff" wide fullword 
        $cmd4 = "RunShell" wide fullword 
        $cmd5 = "StartDDos" wide fullword 
        $cmd6 = "StopDDos" wide fullword 
        $cmd7 = "StartReport" wide fullword 
        $cmd8 = "StopReport" wide fullword 
        $cmd9 = "injRun" wide fullword 
        $cmd10 = "UACFunc" wide fullword 
        $cmd11 = "ngrok+" wide fullword 

        $C21 = "POST / HTTP/1.1" wide fullword
        $C22 = "Host:" wide fullword
        $C23 = "Connection: keep-alive" wide fullword
        $C24 = "Content-Type: application/x-www-form-urlencoded" wide fullword
        $C25 = "User-Agent:" wide fullword
        $C26 = "Content-length: 5235" wide fullword

        $usragnt1 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0" wide
        $usragnt2 = "Mozilla/5.0 (iPhone; CPU iPhone OS 11_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Safari/604.1" wide
        $usragnt3 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36" wide

    condition:
        pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" // DotNet Import Hash 
        and any of ($wide*)
        and any of ($select*)
        and any of ($pwrshll*)
        and any of ($antivm*)
        and any of ($shtdwn*)
        and any of ($usragnt*)
        and 3 of ($C2*)
        and 5 of ($cmd*)
        
 }









