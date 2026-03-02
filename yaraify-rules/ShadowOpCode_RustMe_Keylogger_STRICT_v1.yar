import "pe"

rule ShadowOpCode_RustMe_Keylogger_STRICT_v1 : malware windows keylogger smtp gmail libcurl pe64
{
    meta:
        author          = "ShadowOpCode"
        rule_version    = "1.0"
        date            = "2025-08-31"
        yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "11d819f54b3f00a4b75c480a3f964cf9"
		yarahub_uuid    = "550e8400-e29b-41d4-a716-446655440000"
		yarahub_license = "CC0 1.0"
        description     = "RustMe keylogger x64: WH_KEYBOARD_LL via imports + libcurl SMTP to Gmail + US layout + DebugConfig persistence"
        malware_family  = "RustMe"
        confidence      = "high"
        source          = "Static analysis of RustMe.exe (x64)"
        reference_url   = "https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexa"
        sample_sha256   = "<fill_if_public>"

    strings:
        // Exfiltration
        $smtp_url   = "smtp://smtp.gmail.com:587" ascii
        $gmail_dom  = "gmail.com" ascii
        $gmail_user = "serversreser@gmail.com" ascii
        $subject    = "Subject: Keylogger Report" ascii
        $libcurl    = "libcurl" ascii

        // Keystroke translation
        $tou        = "ToUnicode" ascii
        $mapvk      = "MapVirtualKeyA" ascii
        $kbdstate   = "GetKeyboardState" ascii

        // Keyboard layout
        $load_hkl   = "LoadKeyboardLayoutA" ascii
        $hkl_us     = "00000409" ascii

        // Persistence and artifacts
        $dbg_bat    = "DebugConfig.bat" ascii
        $launcher   = "\\RustMeLauncher\\current" ascii

        // Debug banner
        $started    = "KeyLogger Started" ascii

    condition:
        // PE file and 64-bit
        uint16(0) == 0x5A4D and pe.is_64bit() and

        // Core imports for low-level keyboard hook
        pe.imports("USER32.dll", "SetWindowsHookExA") and
        pe.imports("USER32.dll", "CallNextHookEx") and

        // Gmail SMTP via libcurl (hard indicators)
        all of ($smtp_url, $gmail_dom, $libcurl) and
        1 of ($gmail_user, $subject) and

        // Keystroke translation pipeline
        all of ($tou, $mapvk, $kbdstate) and

        // US layout forcibly loaded
        all of ($load_hkl, $hkl_us) and

        // On-disk artifacts or startup debug banner
        1 of ($dbg_bat, $launcher, $started)
}