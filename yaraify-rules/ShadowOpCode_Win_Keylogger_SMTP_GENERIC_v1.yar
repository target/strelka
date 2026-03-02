import "pe"

rule ShadowOpCode_Win_Keylogger_SMTP_GENERIC_v1 : malware windows keylogger smtp pe64
{
    meta:
        author          = "ShadowOpCode"
        rule_version    = "1.0"
        date            = "2025-08-31"
        tlp             = "CLEAR"
		yarahub_rule_matching_tlp = "TLP:WHITE"
		yarahub_rule_sharing_tlp = "TLP:WHITE"
		yarahub_reference_md5 = "00000000000000000000000000000000"
		yarahub_uuid    = "9f7d1b02-5c2e-4a0c-9d5f-b0a7a8b1f9d2"
		yarahub_license = "CC0 1.0"
        description     = "Windows keylogger (generic): WH_KEYBOARD_LL via imports + ToUnicode pipeline + SMTP artifacts"
        malware_family  = "generic-keylogger-smtp"
        confidence      = "medium"
        source          = "Heuristics from RustMe-like samples"
        reference_url   = "https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexa"

    strings:
        // Keystroke translation
        $tou        = "ToUnicode" ascii
        $mapvk      = "MapVirtualKeyA" ascii
        $kbdstate   = "GetKeyboardState" ascii

        // SMTP artifacts
        $smtp_scheme = "smtp://" ascii
        $header_subj = "Subject:" ascii

        // Key labels commonly used in logs
        $lbl_back    = "(BACKSPACE)" ascii
        $lbl_tab     = "(TAB)" ascii
        $lbl_space   = "(SPACEBAR)" ascii
        $lbl_caps    = "(CAPS_LOCK)" ascii

    condition:
        // PE file and 64-bit
        uint16(0) == 0x5A4D and pe.is_64bit() and

        // Core imports for low-level keyboard hook
        pe.imports("USER32.dll", "SetWindowsHookExA") and
        pe.imports("USER32.dll", "CallNextHookEx") and

        // Keystroke translation pipeline present
        all of ($tou, $mapvk, $kbdstate) and

        // SMTP presence
        $smtp_scheme and

        // Either email header marker or typical key labels
        1 of ($header_subj, $lbl_back, $lbl_tab, $lbl_space, $lbl_caps)
}