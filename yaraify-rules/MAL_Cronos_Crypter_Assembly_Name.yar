import "dotnet"

rule MAL_Cronos_Crypter_Assembly_Name {
    meta:
        description = "Detects Cronos Crypter based on .NET assembly name."
        author = "Tony Lambert"
        yarahub_reference_md5 = "90137ea83b86cd0f07a81156c6a633a8"
        date = "2024-03-17"
		yarahub_uuid = "7e7cf406-dcd1-4244-a595-d2bbc5c41aea"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_license = "CC0 1.0"
    condition:
        dotnet.assembly.name startswith "Cronos-Crypter"
}