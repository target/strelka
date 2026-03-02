import "pe"

rule unpacked_qbot
{
	meta:
		description = "Detects unpacked or memory-dumped QBot samples"
		date = "2022-06-21"
		yarahub_author_twitter = "@z3r0privacy"
		yarahub_reference_md5 = "159E8962C4646EB3ED7C7837F6143F47"
		yarahub_uuid = "a2ad2850-fa12-469f-947a-9dbf79ffcc51"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		malpedia_family = "win.qakbot"

	strings:
		$f_crc = { 33 ?? 8b ?? c1 ?? 04 83 ?? 0f 33 [1-6] 8b ?? c1 ?? 04 83 ?? 0f 33 }
		$c_apihash = { 5b e9 8f 21 }

	condition:
		all of them
		and pe.is_pe and filesize < 1MB
}