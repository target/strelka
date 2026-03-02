
import "pe"

rule APT_CN__Package2_DLL_April2024 {
    meta:
        Description = "Detects malware (Package 2) used by a Chinese APT targeting ASEAN entities"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://unit42.paloaltonetworks.com/chinese-apts-target-asean-entities/"
        File_Hash = "5cd4003ccaa479734c7f5a01c8ff95891831a29d857757bbd7fe4294f3c5c126"
        Info = "This malicious DLL part of the SCR (Package 2) which contains a legit executable, a malicious executable and this DLL"
        date = "2024-04-03"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "720eefb3a1c668f8befc2b365a369d76"
        yarahub_uuid = "7eddc35d-d621-45a3-ae84-f17067ddb9a9"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    
    strings:
        $str1 = "C:\\ProgramData\\updata" wide fullword
        $str2 = "estarmygame" wide

    condition:
        (pe.imphash() == "a069baeb4f8e125a451dc73aca6576b8"
        or (pe.imports("ADVAPI32.dll","RegCloseKey")
        and pe.imports("ADVAPI32.dll","RegOpenKeyExA")
        and pe.imports("KERNEL32.dll","IsProcessorFeaturePresent")
        and pe.imports("KERNEL32.dll","QueryPerformanceCounter")
        and pe.imports("KERNEL32.dll","IsDebuggerPresent")
        and pe.imports("ADVAPI32.dll","RegOpenKeyExA")
        and pe.imports("ADVAPI32.dll","RegSetValueExA")
        and pe.imports("SHELL32.dll","CommandLineToArgvW"))
        and pe.exports("RunServer"))
        and all of them

 }









