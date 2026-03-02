import "pe"

rule MAL_Cronos_Crypter_Strings {
    meta:
        description = "Detects Cronos Crypter based on strings found in file."
        author = "Tony Lambert"
        yarahub_reference_md5 = "90137ea83b86cd0f07a81156c6a633a8"
        date = "2024-03-17"
		yarahub_uuid = "bd4b2f1b-8796-4400-98f5-f460d1884d9e"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_license = "CC0 1.0"
    strings:
        $s1 = "Cronos-Crypter" ascii wide
        $s2 = "Rfc2898DeriveBytes" ascii wide
        $s3 = "RijndaelManaged" ascii wide
    condition:
        pe.is_pe and all of them
}