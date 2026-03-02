import "pe"

rule redline_win_generic
{
	meta:
		author = "_kphi"
		date = "2022-09-10"
		yarahub_uuid = "1172c6d1-7066-4ff1-9d48-c040981d43d4"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "3fdf448f17f65a9677f6597c807060f1"

	strings:
		$a = "GetCurrentProcessId"
		$b = "GetCurrentProcessorNumber"
		$c = "GetCurrentThread"
		$d = "GetCurrentThreadId"
		$e = "GetPriorityClass"
		$f = "GetThreadPriority"
		$g = "TerminateProcess"
		$h = "VirtualProtect"

	condition:
		uint16(0) == 0x5A4D
		and pe.sections[4].name == ".bss"
		and all of them
}
