
import "pe"

rule EXE_gh0st_Dropper_first_stage_March2024
{
  meta:
    author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
    description = "Detects gh0st malware Dropper which contains an embedded second stage payload based on PE properties"
    file_hash = "c0721d7038ea7b1ba4db1d013ce0c1ee96106ebd74ce2862faa6dc0b4a97700d"
    reference = "https://www.first.org/resources/papers/conference2010/cummings-slides.pdf"
    date = "2024-03-23"
    yarahub_author_twitter = "@RustyNoob619"
    yarahub_reference_md5 = "ee13e21a986f19d1259821fe5695a426"
    yarahub_uuid = "ef51f62e-0ea8-473d-b527-6fea30bbd33d"
    yarahub_license = "CC0 1.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
    malpedia_family = "win.ghostnet"
  condition:
    (pe.pdb_path contains "gh0st"
    or pe.imphash() == "e2b4a22dd01bac62ec948d04cee8e739")
    and not pe.pdb_path contains "i386"
    and for any resource in pe.resources:
    (resource.language == 2052                             // Chinese Simplified and resource.
    and resource.type_string == "B\x00I\x00N\x00")        // Embedded DLL Payload 
    
}
