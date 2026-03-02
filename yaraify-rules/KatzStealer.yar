import "pe"

rule KatzStealer
{
	meta:
		date = "2026-01-03"
		description = "Detects KatzStealer executable"
		author = "Nikhil Hegde"
		yarahub_author_twitter = "@ka1do9"
		reference = "nikhilh-20.github.io/blog/"
		yarahub_reference_md5 = "f175f4c2d99cc4f35f9aecdffc3489ed"
		yarahub_uuid = "ebda07ec-beca-45dc-aac7-d2c89bf0052d"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"

	strings:
		$ = "encrypted_key" nocase
		$ = "chrome.exe" nocase
		$ = "MASTERKEY.txt" nocase
		$ = "_copy.db" nocase
		$ = "screenshot" nocase
		$ = "-headless" wide ascii nocase

	condition:
		pe.is_pe and
		all of them
}