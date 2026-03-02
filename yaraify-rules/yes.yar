rule yes
{

	meta:
		date = "2023-07-24"
		yarahub_uuid = "aad162a4-d304-423e-b478-ae82f28691d7"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "7d066ca5aabee7ca02095468d7cb5202"
	strings:

		$a = "0"

		$b = "0" wide ascii
		$c = "0" wide
		$d = "1"
		$d1 = "1" wide
		$d2 = "1" wide ascii
		$d3 = "true"
		$d4 = "false"
		$d5 = "true" wide ascii
		$d6 = "false" wide ascii
		$d7 = "true" wide
		$d8 = "false" wide
	condition:

		undefined or false or true
}
