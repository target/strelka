import "pe"


rule signed_sys_with_vulnerablity {
    meta:
		description = "signed_sys_with_vulnerablity"
        date = "2023-07-21"
        author ="wonderkun"
        yarahub_reference_md5     = "3b25a34bb08f4759792c24b121109513"
        yarahub_uuid = "615591f5-2e81-4c01-8ebf-ab8aade6efcf"
        yarahub_license =  "CC0 1.0"
        yarahub_rule_matching_tlp =  "TLP:WHITE"
        yarahub_rule_sharing_tlp =  "TLP:WHITE"
        tlp = "WHITE"

    strings:
        $MmMapIoSpace = "MmMapIoSpace"
        $MapViewOfSection = "MapViewOfSection"
        $PhysicalMemory = "PhysicalMemory"
	condition:
		(pe.imports("ntoskrnl.exe") and pe.number_of_signatures > 0)
        and
        ($MmMapIoSpace or $MapViewOfSection or $PhysicalMemory)
}
