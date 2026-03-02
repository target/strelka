import "pe"

rule vulnerablity_driver2_PhysicalMemory {
    meta:
		description = "vulnerablity_driver2_PhysicalMemory"
        date = "2023-07-21"
        author ="wonderkun"
        yarahub_reference_md5     = "3b25a34bb08f4759792c24b121109503"
        yarahub_uuid = "34512c64-fa1a-472b-89d7-ff36fafb943d"
        yarahub_license =  "CC0 1.0"
        yarahub_rule_matching_tlp =  "TLP:WHITE"
        yarahub_rule_sharing_tlp =  "TLP:WHITE"
        tlp = "WHITE"
    strings:
        $PhysicalMemory = "\\Device\\PhysicalMemory"
        $PhysicalMemory_Wide = "\\Device\\PhysicalMemory" wide
	condition:
        pe.is_64bit()
        and
        filesize > 3000KB
		and
		filesize < 10000KB
        and
        (pe.number_of_signatures >0)
        and
        (
            for all i in (0..pe.number_of_signatures - 1):
            (
            pe.signatures[i].valid_on(pe.timestamp)
            )
        )
        and
		(pe.imports("ntoskrnl.exe","ZwMapViewOfSection") or pe.imports("ntoskrnl.exe","NtMapViewOfSection"))
        and
        (($PhysicalMemory) or ($PhysicalMemory_Wide))
}

