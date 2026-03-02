import "pe"

rule agenttesla_win_generic
{
	meta:
		author = "_kphi"
		date = "2022-09-10"
		yarahub_uuid = "d595c952-21c9-40ec-8d18-ea91cba4f197"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "ffaa02061474361bc88fbdbbe1c0737d"

	strings:
		$a = "MyApplication.app"
		$b = "CallByName"
		
	condition:
		uint16(0) == 0x5A4D
		and pe.version_info["CompanyName"] contains "Microsoft Corporation"
		and pe.version_info["FileDescription"] contains "SetupCleanupTask"
		and pe.version_info["ProductName"] contains "SetupCleanupTask"
		and all of them
}
