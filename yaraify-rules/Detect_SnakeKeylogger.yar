import "pe"
import "math"

rule Detect_SnakeKeylogger
{
    meta:
        description = "Detect first stage .NET binary of Snake keylogger infection"
        author      = "txc"
        date        = "2025-08-03"
        reference   = "https://medium.com/@0x747863/malware-analysis-snake-keylogger-snake-stealer-bbcc91705089"
        yarahub_uuid = "876b0bf5-502e-453f-b5a0-066fde672dd7"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "9102aaecaa9cfc4af9958c84cb7ebad8"

    strings:
        $clr_header  = { 42 53 4A 42 }  // CLR metadata signature "BSJB"
        $latecall   = { 11 14 14 72 59 03 00 70 18 8D 16 00 00 01 25 16 16 8C 4C 00 00 01 A2 25 17 11 12 A2 14 14 28 88 00 00 0A } // latecall used to reflectivly load next stage DLL

    condition:
        uint16(0) == 0x5A4D and
        $clr_header and
        $latecall and

        for any i in (0..pe.number_of_sections - 1): // high entropy in .text section
            (
                pe.sections[i].name == ".text" and
                math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) >= 7.5
            )
}