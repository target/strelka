import "pe"


rule ItsSoEasy_Ransomware_Py_Var {
    meta:
		description = "Detect ItsSoEasy Ransomware (Itssoeasy-A Py.Var)"
		author = "bstnbuck"
		date = "2023-11-02"
        yarahub_author_twitter = "@bstnbuck"
        yarahub_reference_link = "https://github.com/bstnbuck/ItsSoEasy"
        yarahub_uuid = "d4a753c7-fd2d-482c-8e4f-bba0766a9e07"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "71a3802f52847e83d3bacd011451b595"
    
	strings:
		$typ1 = "itssoeasy" nocase
		$typ1_wide = "itssoeasy" nocase wide
		$typ2 = "itssoeasy" base64
		$typ3 = "ItsSoEasy" base64

		// other strings
		$a1 = "pyi-windows-manifest-filename"
		$a2 = "_PYI_PROCNAME"	

    condition:
        any of ($typ*) and (($a1 and pe.number_of_resources > 0) or $a2) and filesize > 8MB and filesize < 16MB
}


