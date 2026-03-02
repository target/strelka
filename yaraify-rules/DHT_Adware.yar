import "pe"

rule DHT_Adware
{
    meta:
        description = "Detects DHT Adware ecosystem"
        author = "rifteyy"
        date = "2026-02-09"
        blog_reference = "https://rifteyy.org/report/anypdf-malware-analysis"
        hash1 = "b8dd436636a416eb9b55431ed7b60eb14771ad93e972f1248b8d8149d4ee5272"
        hash2 = "ea09fb40963340b212833e796f229ff52e80c66c4354fbe1107cecc07d3c988a"
        hash3 = "ad8322170e39cb1ace157e0bb0bbffd71cf7e11f602c29f273109acc7329b579"
        hash4 = "ce2f4094704b579018e2e8ba4f2c1f14d9072f3c405298e42df6c4eb6a1bed37"
        hash5 = "b172d7a7593e0a1d596413bd3e24071fd0fa85168268b52c45c7f7540787216e"
        severity = "Medium"

	yarahub_rule_matching_tlp = "TLP:WHITE"
	yarahub_rule_sharing_tlp = "TLP:WHITE"
	yarahub_uuid = "cabd00f9-34a5-4445-a8de-7e0d0018b2be"
	yarahub_license = "CC BY 4.0"
	yarahub_reference_md5 = "d051952399ddea1548af4a7fdf1d1574"

    strings:
        $filename = "DownloadHelperTray" ascii wide
        $DHTstring1 = "CookieDecrypt" ascii wide
        $DHTstring2 = "GetEncryptedValueFromNameEdge" ascii wide
        $DHTstring3 = "GetEncryptedValueFromNameFirefox" ascii wide
        $DHTstring4 = "CreateDecryptor" ascii wide
	$DHTstring5 = "AdUrlReceived" ascii wide
        $DHTstring6 = "ErrorOpenAdUrl" ascii wide
        $DHTstring7 = "ErrorReadingCookies" ascii wide
        $DHTstring8 = "AddUrlObtained" ascii wide
        $DHTstring9 = "AddUrlNull" ascii wide

        $method1 = "OpenAdUrlInHiddenBrowser" ascii wide
        $method2 = "IsAppRunningInVirtualMachine" ascii wide
        $method3 = "OverrideBrowserCrashReport" ascii wide
        $method4 = "CheckIfAnyAdUrlWasCalledTwice" ascii wide
        $method5 = "GetAdUrl" ascii wide

        $string1 = "DiagnosticDriverUpdateJson" ascii wide
        $string2 = "AutoUpdater" ascii wide

        $dlMethod1 = "StopProcessReplaceFilesAndStartProcess" ascii wide
        $dlMethod2 = "DownloadAndExtractZip" ascii wide
        $dlMethod3 = "CheckSingleInstanceMutex" ascii wide

        $config1 = "JsonConfig" ascii wide
        $config2 = "ZipConfig" ascii wide
        $config3 = "ServerConfig" ascii wide

    condition:
        uint16(0) == 0x5A4D and 
        pe.imports("mscoree.dll") and
        (
            (3 of ($DHTstring*) or ($filename and 2 of ($DHTstring*)))
            or
            (3 of ($method*))
            or
            ((all of ($config*) and 1 of ($string*)) or 2 of ($dlMethod*))
        )
}