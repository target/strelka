import "pe"

rule TTP_Chinese_Dropper_March2024
{
  meta:
    author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
    description = "Detects Exetutables which are written in the Chinese Simplified Language and contain an embedded DLL within them"
    file_hash = "c0721d7038ea7b1ba4db1d013ce0c1ee96106ebd74ce2862faa6dc0b4a97700d"
    reference = "https://www.first.org/resources/papers/conference2010/cummings-slides.pdf"
    date = "2024-03-22"
    yarahub_author_twitter = "@RustyNoob619"
    yarahub_reference_md5 = "ee13e21a986f19d1259821fe5695a426"
    yarahub_uuid = "ad6415b7-81ff-4267-9da5-726e2b1f24e2"
    yarahub_license = "CC0 1.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
    
  condition:
    pe.number_of_resources == 1
    and for any resource in pe.resources:
    (resource.language == 2052                             // Chinese Simplified and resource.
    and resource.type_string == "B\x00I\x00N\x00")        // Embedded DLL Payload 
    
}