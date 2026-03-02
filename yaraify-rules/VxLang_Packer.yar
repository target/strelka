import "pe"

rule VxLang_Packer
{
  meta:
    author = "P4nd3m1cb0y"
    description = "Detects executables packed with VxLang"
    target_entity = "file"
    status = "RELEASED"
    date = "2023-11-14"
    yarahub_author_twitter = "@P4nd3m1cb0y"
    yarahub_reference_link = "https://github.com/vxlang/vxlang-page"
    yarahub_reference_md5 = "6c4d797d402ae5519c33f85e33d45fb6"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
    yarahub_license = "CC0 1.0"
    yarahub_uuid = "10fa6ea1-d58a-4cc6-89cc-fa1ca57a3050"
    hash = "7d9304eeb8f4c5823eecbedde65cc2877c809824c9203d16221c70eb591ee8ce"

  condition:
    uint16(0) == 0x5a4d and 
    for any i in (0 .. pe.number_of_sections) : (
        pe.sections[i].name contains ".vxil"
    )
}
