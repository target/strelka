import "pe"
import "dotnet"

rule APT_Bitter_Almond_RAT {
    
    meta:
        description = "Detects Bitter (T-APT-17) Almond RAT (.NET)"
        author = "SECUINFRA Falcon Team (@SI_FalconTeam)"
        tlp = "WHITE"
        yarahub_uuid = "5f969f39-809d-43a5-9385-83af01b66707"
        yarahub_reference_md5 = "71e1cfb5e5a515cea2c3537b78325abf"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_author_twitter = "@SI_FalconTeam"
        reference = " https://www.secuinfra.com/en/techtalk/whatever-floats-your-boat-bitter-apt-continues-to-target-bangladesh"
        date = "2022-06-01"
        hash = "55901c2d5489d6ac5a0671971d29a31f4cdfa2e03d56e18c1585d78547a26396"

    strings:
        $function0 = "GetMacid" ascii
        $function1 = "StartCommWithServer" ascii
        $function2 = "sendingSysInfo" ascii

        $dbg0 = "*|END|*" wide
        $dbg1 = "FILE>" wide
        $dbg2 = "[Command Executed Successfully]" wide

    condition:
        uint16(0) == 0x5a4d
        and dotnet.version == "v4.0.30319"
        and filesize > 12KB // Size on Disk/1.5
        and filesize < 68KB // Size of Image*1.5
        and any of ($function*)
        and any of ($dbg*)
}