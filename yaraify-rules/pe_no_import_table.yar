import "pe"

rule pe_no_import_table {
    meta:
        description = "Detect pe file that no import table"
        date = "2021-10-19"
        yarahub_uuid = "a91fb4f4-1ceb-456d-90d1-a25f6d16b204"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "045ff7ed5a360b19dcc4c5bd9211d194"
    condition:
        pe.is_pe
        and pe.number_of_imports == 0
}