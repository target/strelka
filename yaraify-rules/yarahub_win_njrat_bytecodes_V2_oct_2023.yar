
import "dotnet"


rule yarahub_win_njrat_bytecodes_V2_oct_2023
{
	meta:
		author = "Matthew @ Embee_Research"
		yarahub_author_twitter = "@embee_research"
		desc = "Bytecodes present in njrat malware"
		sha_256 = "9877fc613035d533feda6adc6848e183bf8c8660de3a34b1acd73c75e62e2823"
		sha_256 = "40f07bdfb74e61fe7d7973bcd4167ffefcff2f8ba2ed6f82e9fcb5a295aaf113"
		date = "2023-09-13"
        yarahub_uuid = "f514233e-7b4c-4efe-81ad-eaf069a35ba4"
       	yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "68ba6d9812051a668115149f195b1956"
        malpedia_family = "win.njrat"
		
		
		
	strings:
		$s1 = {03 1F 72 2E ?? 03 1F 73 2E ?? 03 1F 74 2E ?? 03 1F 75 2E ?? 03 1F 76 2E ?? }
		$s2 = {0B 14 0C 16 0D 16 13 ?? 16 13 ?? 14}
		

	condition:
		dotnet.is_dotnet
		
		and
	
		(all of ($s*))
		

}