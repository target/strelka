import "pe"

rule EXE_gh0st_RootKit_first_stage_March2024
{
  meta:
    author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
    description = "Detects gh0st Root Kit malware Dropper which contains an embedded second stage payload based on PE properties"
    file_hash = "f4041d6ad6fc394295bd976b45d092f4f36a90805705c048c637710f422632f0"
    reference = "https://www.first.org/resources/papers/conference2010/cummings-slides.pdf"
    date = "2024-03-24"
    yarahub_author_twitter = "@RustyNoob619"
    yarahub_reference_md5 = "cf2352d630d808396044ff29975a5ac1"
    yarahub_uuid = "7832449d-f8ef-428b-92d4-a650f67024de"
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
    $str1 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor"
    $str2 = "_kaspersky" fullword ascii
    $str3 = "\\.\\RESSDTDOS" fullword ascii

  condition:
    for any resource in pe.resources:
    (resource.language == 2052                             // Chinese Simplified and resource.
    and resource.type_string == "B\x00I\x00N\x00")        // Embedded DLL Payload
    and any of ($ghost*)
    and any of ($str*)
    
}
