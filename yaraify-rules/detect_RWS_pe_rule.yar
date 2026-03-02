import "pe"

rule detect_RWS_pe_rule
{
	meta:
		description = "Detects RWX-S signed binaries. This only verifies that the image contains a signature, not that it is valid."
		author = "Bill Demirkapi"
        date = "2023-07-21"
        author ="wonderkun"
        yarahub_reference_md5     = "3b25a34bb08f4759792c24b121109506"
        yarahub_uuid = "63596a4a-c95c-474c-b04f-6315e2093567"
        yarahub_license =  "CC0 1.0"
        yarahub_rule_matching_tlp =  "TLP:WHITE"
        yarahub_rule_sharing_tlp =  "TLP:WHITE"
        tlp = "WHITE"

	condition:
		for any i in (0..pe.number_of_sections - 1): (
			(pe.sections[i].characteristics & pe.SECTION_MEM_READ) and
			(pe.sections[i].characteristics & pe.SECTION_MEM_EXECUTE) and
			(pe.sections[i].characteristics & pe.SECTION_MEM_WRITE) and
			(pe.sections[i].characteristics & pe.SECTION_MEM_SHARED) )
		and pe.number_of_signatures > 0
}