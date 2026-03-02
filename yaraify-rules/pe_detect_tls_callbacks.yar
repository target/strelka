import "pe"

rule pe_detect_tls_callbacks {

    meta:
        date = "2024-07-26"
        yarahub_uuid = "881c8cad-35ef-414d-8906-0f98f7b37cd6"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "13794d1d8e87c69119237256ef068043"

     condition:
        uint16(0) == 0x5a4d and pe.data_directories[9].virtual_address != 0 and  pe.data_directories[9].size != 0
}