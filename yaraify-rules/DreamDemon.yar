rule DreamDemon {
	meta:
		author = "Jonathan Beierle"
		description = ""
		rule_category = "Malware Family"
		yarahub_uuid = "60bbdc4d-d22c-403e-b01f-7e4aa8ed3e3b"
		yarahub_reference_md5 = "d924fbc8593427d9b7cc4bd7bd899718"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		date = "2025-11-18"
		date_created = "25 August 2025"
		date_updated = ""
		reference = "https://beierle.win/2025-08-28-A-Nightmare-on-EDR-Street-WDACs-Revenge/"
	strings:
		/* References to WDAC-related locations
			"\\C$\\System32\\CodeIntegrity\\SiPolicy.p7b"
			"\\ADMIN$\\System32\\CodeIntegrity\\SiPolicy.p7b"
			"%windir%\\System32\CodeIntegrity\\SiPolicy.p7b"
			"%systemroot%\\System32\CodeIntegrity\\SiPolicy.p7b"
		*/
		$path_ref = "\\System32\\CodeIntegrity\\SiPolicy.p7b" ascii wide
		
		// Parameters for CreateFileA which hide the WDAC policy
		$hide_file_1 = {
			68 02 ?? ?? ??          // push 80000002h ; dwFlagsAndAttributes
			6A 0?                   // push 1         ; dwCreationDisposition
			6A ??                   // push 0         ; lpSecurityAttributes
			6A ??                   // push 0         ; dwShareMode
			68 00 00 00 40          // push 40000000h ; dwDesiredAccess
		}
		
		// Parameters for SetFileAttributesA to hide the WDAC policy
		$hide_file_2 = {
			6A 02                   // push 2                     ; dwFileAttributes 
			8D ?? ??                // lea ecx, [ebp+var_30]
			E8 ?? ?? ?? ??          // call sub_408910
			50                      // push eax                   ; lpFileName
			FF                      // call ds:SetFileAttributesA ; Full instruction omitted for optimization
		}
	condition:
		uint16(0) == 0x5A4D
		and $path_ref
		and MALDAC
		and 1 of ($hide_file_*)
}