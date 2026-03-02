import "pe"

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
