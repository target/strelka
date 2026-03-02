import "pe"

rule Luckyware_Infection_Detection
{
    meta:
        description = "Comprehensive detection for Luckyware RAT: covers PE/DLL infection, temp files, and C2 indicators"
        author = "Kamerzystanasyt"
        date = "2026-01-07"
        yarahub_uuid = "ffbcf56e-a1cc-43d7-a11c-a0490fa2840a"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "875F2C945D3069499FB9897B329C1E98"
        category = "RAT"
        severity = "Critical"
        actor_type = "LUCKYWARE"
        reference = "https://github.com/Emree1337/Luckyware"

    strings:
        // ox_1758042820730.exe
        $temp_naming = /(ox_|[A-Z]{2,3})[0-9]{10,13}(\.exe)?/

        // domains
        $d1 = "devruntime.cy" nocase
        $d2 = "zetolacs-cloud.top" nocase
        $d3 = "frozi.cc" nocase
        $d4 = "exo-api.tf" nocase
        $d5 = "nuzzyservices.com" nocase
        $d6 = "darkside.cy" nocase
        $d7 = "balista.lol" nocase
        $d8 = "phobos.top" nocase
        $d9 = "phobosransom.com" nocase
        $d10 = "pee-files.nl" nocase
        $d11 = "vcc-library.uk" nocase
        $d12 = "luckyware.co" nocase
        $d13 = "luckyware.cc" nocase
        $d17 = "risesmp.net" nocase
        $d18 = "i-like.boats" nocase
        $d19 = "luckystrike.pw" nocase
        $d20 = "krispykreme.top" nocase
        $d21 = "vcc-redistrbutable.help" nocase
        $d22 = "i-slept-with-ur.mom" nocase

        // namespace infection
        $ns1 = "namespace VccLibaries" nocase
        $ns2 = "namespace SDKInfector" nocase
        $func1 = "Bombakla" nocase
        $func2 = "Rundollay" nocase

        $mz = { 4D 5A }

    condition:
        (uint16(0) == 0x5A4D and (
            $temp_naming or 
            any of ($d*) or 
            any of ($ns*) or 
            any of ($func*) or
            pe.exports("profapi.dll") or 
            pe.exports("omadmapi.dll") or
            #mz > 1
        ))
}