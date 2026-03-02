import "pe"

rule DLL_gh0st_Rootkit_second_stage_March2024
{
  meta:
    author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
    description = "Detects gh0st RAT which is the second stage paylaod dropped by gh0st Root kit"
    file_hash = "1a51096110781e3abdb464196fff9ecb218ccf9a897469b1a99c5ec94f5b1694"
    reference = "https://www.first.org/resources/papers/conference2010/cummings-slides.pdf"
    date = "2024-03-24"
    yarahub_author_twitter = "@RustyNoob619"
    yarahub_reference_md5 = "37bfe694cae595b90e3e62a0a33401ed"
    yarahub_uuid = "914bf729-b2be-46c3-949f-1e67c170bb9e"
    yarahub_license = "CC0 1.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
    malpedia_family = "win.ghostnet"
  strings:
    $ghost1 = "Gh0st Update" fullword ascii 
    $ghost2 = "Global\\Gh0st %d" fullword ascii 
    $ghost3 = "gh0st\\server\\sys\\i386\\RESSDT.pdb"
    $ghost4 = "gh0st3.6_src\\HACKER\\i386\\HACKE.pdb"
    $ghost5 = "gh0st3.6_src\\Server\\sys\\i386\\CHENQI.pdb"
    $str1= "\\Device\\RESSDT"
    $str2= "\\??\\RESSDTDOS"
    $str3= "\\.\\RESSDTDOS"
    $str4= "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"

  condition:
    pe.imphash() == "5c38312da54af04f6a40592477000188"
    or (pe.imports("SHELL32.dll","SHGetSpecialFolderPathA")
    and pe.imports("SHLWAPI.dll","SHDeleteKeyA")
    and pe.imports("AVICAP32.dll","capGetDriverDescriptionA")
    and pe.imports("MSVFW32.dll","ICSendMessage")
    and pe.imports("PSAPI.DLL","EnumProcessModules")
    and pe.imports("WTSAPI32.dll","WTSFreeMemory"))
    and pe.exports("ResetSSDT")
    and pe.exports("ServiceMain")
    and pe.resources[0].language == 2052
    and any of ($ghost*)
    and any of ($str*)
    
}