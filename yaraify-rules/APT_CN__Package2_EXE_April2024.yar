
import "pe"

rule APT_CN__Package2_EXE_April2024 {
    meta:
        Description = "Detects malware (Package 2) used by a Chinese APT targeting ASEAN entities"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://unit42.paloaltonetworks.com/chinese-apts-target-asean-entities/"
        File_Hash = "02f4186b532b3e33a5cd6d9a39d9469b8d9c12df7cb45dba6dcab912b03e3cb8"
        Info = "This malicious EXE part of  SCR (Package 2) which contains a legit executable, a malicious DLL and this EXE"
        date = "2024-04-04"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "602d71d51d266c805b8afd4289851218"
        yarahub_uuid = "d4409ac0-feb8-44ae-bf55-48b43b49e300"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    
    strings:
        $str1 = "http://" wide fullword
        $str2 = "FWININET.DLL" wide fullword
        $str3 = "TKernel32.dll" wide fullword
        $str4 = "TComdlg32.dll" wide fullword

        $path1 = "C:\\Users\\Public\\EACore.dll" wide
        $path2 = "C:\\Users\\Public\\WindowsUpdate.exe" wide

        $url1 = "http://123.253.32.71/EACore.dll" wide
        $url2 = "http://123.253.32.71/WindowsUpdate.exe" wide

    condition:
        (pe.imphash() == "cf4236da1b59447c2fe49d31eb7bb6e2"
        or (pe.imports("UxTheme.dll","GetWindowTheme")
        and pe.imports("SHLWAPI.dll","PathIsUNCW")
        and pe.imports("MSIMG32.dll","AlphaBlend")
        and pe.imports("OLEACC.dll","AccessibleObjectFromWindow")
        and pe.imports("WINMM.dll","PlaySoundW")
        and pe.imports("ole32.dll","DoDragDrop")
        and pe.imports("ADVAPI32.dll","SystemFunction036")
        and pe.imports("SHELL32.dll","SHGetSpecialFolderLocation")
        and pe.imports("WINSPOOL.DRV","DocumentPropertiesW")))
        
        and (2 of ($str*)
        or any of ($path*)
        or any of ($url*))

 }










