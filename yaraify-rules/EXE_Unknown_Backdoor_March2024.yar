import "pe"
import "math"

rule EXE_Unknown_Backdoor_March2024 {
    meta:
        Description = "Detects an unknown backdoor"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Credits = "@naumovax for sharing the malware sample on Twitter"
        Reference = "https://twitter.com/naumovax/status/1765723034369872043"
        Hash = "ddf7b9bf24b19ee183d788f482a01e517048587e8ce21f5d32c927f6f0371824"
        date = "2024-03-07"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "ab3b45315e4054bf80adea0e2646ff32"
        yarahub_uuid = "c821b404-58c7-411d-bad6-ebf27e7d7337"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    
    strings:
        $str1 = "sNbUdD"
        $str2 = "U,.-.._"

    condition:
        pe.number_of_sections == 3
        and for any section in pe.sections:
        (math.entropy(section.raw_data_offset, section.raw_data_size) > 7.84)
        and pe.imports("KERNEL32.DLL","VirtualAlloc")
        and pe.imports("KERNEL32.DLL","VirtualProtect")
        and pe.imports("KERNEL32.DLL","GetProcAddress")
        and pe.imports("ADVAPI32.DLL","DeleteService")
        and pe.imports("SHELL32.DLL","ShellExecuteA")
        and pe.imports("MSVCRT.DLL","printf")
        and pe.imports("WS2_32.DLL",116) // Ordinal 
        and all of them

}