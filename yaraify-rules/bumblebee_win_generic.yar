import "pe"

rule bumblebee_win_generic
{
	meta:
		author = "_kphi"
		date = "2022-09-13"
		yarahub_uuid = "2644a2db-481d-4efb-94b4-309a4e73bccc"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "29a405557da7bb24b2f278c5c46dfd3c"

	strings:
		$a1 = "FindFirstFile"
		$a2 = "FindNextFile"
		$a3 = "HeapWalk"
		$a4 = "GetCurrentProcessId"
		$a5 = "GetCurrentThreadId"
		$a6 = "MapViewOfFile"
		$a7 = "SwitchToFiber"
		$a8 = "DeleteFiber"
		$a9 = "RtlLookupFunctionEntry"
		$a10 = "TerminateProcess"
		$a11 = "GetModuleHandleEx"
		$a12 = "FindFirstFileEx"
		$a13 = "GetEnvironmentStrings"
		$a14 = "WriteFile"
		$a15 = "RaiseException"
		
	condition:
		uint16(0) == 0x5A4D
		and pe.exports("DllRegisterServer")
		and 12 of them
}
