import "pe"

rule StrelaStealer {
	meta:
        author = "@hackNpatch@infosec.exchange"
        date = "2022-11-11"
        yarahub_author_twitter = "@hackpatch"
        yarahub_reference_sha256 = "8b0d8651e035fcc91c39b3260c871342d1652c97b37c86f07a561828b652e907"
		yarahub_reference_md5 = "57EC0F7CF124D1AE3B73E643A6AC1DAD"        
		yarahub_reference_link = "https://medium.com/@DCSO_CyTec/shortandmalicious-strelastealer-aims-for-mail-credentials-a4c3e78c8abc"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_uuid = "9dbbc74b-fdf0-475f-a2df-0478ab5299e1"

	strings:
		$pdbstring = "C:\\Users\\Serhii\\Documents\\Visual Studio 2008\\Projects\\StrelaDLLCompile\\Release\\StrelaDLLCompile.pdb"
	
	condition:
		pe.DLL
		and pe.number_of_exports == 1
		and ($pdbstring or pe.exports("s") or pe.exports("Strela"))

}