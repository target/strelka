
import "pe"

rule EXE_Stealer_Planet_March2024
{
  meta:
    author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
    description = "Detects Planet Stealer malware"
    Source = "https://inquest.net/blog/around-we-go-planet-stealer-emerges/"
    File_Hash = "e846d3cfad85b09f8fdb0460fff53cfda1176f4e9e420bf60ed88d39b1ef93db"
    date = "2024-03-11"
    yarahub_author_twitter = "@RustyNoob619"
    yarahub_reference_md5 = "f364d1b15bb2049549d9084496ad239b"
    yarahub_uuid = "8a5972c0-015e-494f-9f96-6bbd9f012fd0"
    yarahub_license = "CC0 1.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"

  strings:
    $go = "Go buildinf:"
    $hex = {504534746952}

  condition:
    pe.imphash() == "9aebf3da4677af9275c461261e5abde3"
    and pe.number_of_sections == 3
    and pe.sections[0].name == "UPX0"
    and $go
    and $hex
    and filesize > 4MB and filesize < 5MB
}





 

 