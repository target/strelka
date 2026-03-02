
import "pe"

rule DLL_North_Korean_Lazarus_March2024 {
    meta:
        Description = "Detects a malicious DLL used by a North Korean Threat actor Lazarus"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Credits = "@BaoshengbinCumt for sharing the malware sample on Twitter"
        Reference = "https://twitter.com/BaoshengbinCumt/status/1767422816507646073"
        Hash = "5289529957d52c9d5fc2e47aa9924fd1de21b902509dee0241d5d6b056733a94"
        date = "2024-03-13"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "caa16eb9c17c381a6d80c821fb0daf0a"
        yarahub_uuid = "6e074788-ddce-4a8d-869b-ac54518397ec"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $str1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections" wide
        $str2 = "SeDebugPrivilege" wide
        $str3 = "AutoConfigURL" wide

        $usragnt1 = "Content-Length:" wide
        $usragnt2 = "Content-Type: application/x-www-form-urlencoded" wide

        $cmd1 = "opt %lu(%lu) stat %lu(%lu) stored %lu lit %u dist %u"
        $cmd2 = "dist data: dyn %ld, stat %ld"
        $cmd3 = "lit data: dyn %ld, stat %ld"
        $cmd4 = "dyn trees: dyn %ld, stat %ld"
        $cmd5 = "code %d bits %d->%d"
        $cmd6 = "bl code %2d"

    condition:
        pe.imports("KERNEL32.dll","UpdateProcThreadAttribute")
        and pe.imports("KERNEL32.dll","QueryPerformanceCounter")
        and pe.imports("KERNEL32.dll","IsDebuggerPresent")
        and pe.imports("KERNEL32.dll","GetUserDefaultLCID")
        and pe.imports("ole32.dll","CoInitializeEx")
        and pe.imports("ole32.dll","CoInitializeSecurity")
        and pe.imports("SHELL32.dll","CommandLineToArgvW")
        and pe.imports("ADVAPI32.dll","LookupPrivilegeValueW")
    
        and pe.exports("InitProcessPriv")
        and pe.exports("InitThread")
        and pe.exports("ShutdownLockAppHostServer")
        and pe.exports("StartLockAppHostServer")
        and pe.exports("UnInitProcessPriv")
        and pe.exports("UnInitThread")
        and 2 of ($str*)
        and any of ($usragnt*)
        and 3 of ($cmd*)
}

 




 

 


 




 

 