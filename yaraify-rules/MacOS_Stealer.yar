rule MacOS_Stealer
{
    meta:
        description = "Detects MacOS stealer malware attributed to 'mentalpositive'"
        author = "dogsafetyforeverone"
        date = "2025-04-20"
        version = "1.0"
        malware_family = "MacOSStealer"
        reference = "MacOS stealer malware"
        yarahub_reference_md5 = "342dda1ffc615e5f954481fecd765dd3"
        yarahub_uuid = "3df114d9-6cef-454c-9de7-90b41870f657"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $func1 = "_CollectBrowsers"
        $func2 = "_CollectCryptowallets"
        $func3 = "_CollectData"
        $func4 = "_CollectExtensions"
        $func5 = "_CollectSync"
        $func6 = "_ExtensionsID"
        $func7 = "_ExtractPassword"
        $func8 = "_GetPasswordModal"
        $func9 = "_GetProfiles"
        $func10 = "_PasswordValidator"

    condition:
        all of ($func*)
}
