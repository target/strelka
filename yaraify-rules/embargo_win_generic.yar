import "pe"

rule embargo_win_generic
{
	meta:
		author = "_kphi"
		date = "2024-11-05"
		yarahub_uuid = "d44d02e5-a22b-46c4-b433-02bab3950fed"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "5d55fb708834d5ccde15d36554ea63e8"

	strings:
		$a1 = ".cargo/registry/src/index.crates.io"
		$a2 = "[+] Finish encrypted"
		$a3 = "Deleted  shadows"
		$a4 = "embargo::winlib::encryptsrc/winlib/encrypt.rs"
		$a5 = "cmd.exe/q/cbcdedit/set{default}recoveryenabledno"
		
	condition:
		uint16(0) == 0x5A4D and
		all of them
}
