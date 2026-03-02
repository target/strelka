import "pe"

rule Detect_NSIS_Nullsoft_Installer : NSIS
{
    meta:
        author                       = "Obscurity Labs LLC"
        description                  = "Detects NSIS installers by .ndata section + NSIS header string"
        date                         = "2025-06-06"
        version                      = "1.0.0"
        yarahub_author_twitter       = "@obscuritylabs"
        yarahub_reference_md5        = "c3fc97f82241d6d91c6d037190b3753c"
        yarahub_uuid                 = "90626ac0-e544-4d5b-b8c3-e70a7feb2b69"
        yarahub_license              = "CC BY-NC 4.0"
        yarahub_rule_matching_tlp    = "TLP:WHITE"
        yarahub_rule_sharing_tlp     = "TLP:WHITE"

    strings:
        // Wide-string "NSIS Error" (UTF-16LE)
        $nsis_error_w = "NSIS Error" wide nocase
        // Wide-string "NSIS" (UTF-16LE)
        $nsis_w = "NSIS" wide nocase
        // Wide-string "Nullsoft" (UTF-16LE)
        $nullsoft_w = "Nullsoft" wide nocase

    condition:
        pe.number_of_sections > 0 and
        for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].name == ".ndata"
        )
        and
        (
            any of ($nsis_error_w) or
            any of ($nsis_w) or
            any of ($nullsoft_w)
        )
}