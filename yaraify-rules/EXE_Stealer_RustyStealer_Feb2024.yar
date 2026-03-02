
import "pe"

rule EXE_Stealer_RustyStealer_Feb2024 {
    meta:
        Description = "Detects Rusty Stealer malware"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://bazaar.abuse.ch/browse/signature/RustyStealer/"
        Hash = "d9e9008e6e668b1c484f7afe757b1102bb930059b66ef5f282c472af35778c28"
        date = "2024-02-26"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "915e45bdd9ab88edc45ec036df811eb0"
        yarahub_uuid = "3e3e5056-9618-47b5-a34d-7aabeaa6d1ac"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
      
    strings:
        $rust1 = "/rustc/cc66ad468955717ab92600c770da8c1601a4ff33\\library\\alloc\\src\\collections\\btree\\map\\entry.rsh"
        $rust2 = "/rustc/cc66ad468955717ab92600c770da8c1601a4ff33\\library\\core\\src\\slice\\iter.rs"
        $rust3 = "/rustc/cc66ad468955717ab92600c770da8c1601a4ff33\\library\\core\\src\\fmt\\mod.rs"
        $rust4 = "G:\\RUST_DROPPER_EXE_PAYLOAD\\DROPPER_MAIN\\pe-tools\\src\\shared"
        $rust5 = "G:\\RUST_DROPPER_EXE_PAYLOAD\\DROPPER_MAIN\\pe-tools\\src\\x64.rs"
        $rust6 = "\\.\\pipe\\__rust_anonymous_pipe1__."
        $rust7 = "Local\\RustBacktraceMutex00000000"
        
        $unref = "AppPolicyGetProcessTerminationMethod"

        $susurl = "https://reboot.show/boredape/downloadx.cmdsrc\\main.rs"

    condition:
        pe.number_of_signatures == 0
        and pe.imphash() == "88a2d6e140afe5bcad7a3b6bdb449e9c"
        or (
            pe.imports("ntdll.dll","RtlNtStatusToDosError")
            and pe.imports("bcrypt.dll","BCryptGenRandom")
            and pe.imports("secur32.dll","FreeCredentialsHandle")
            and 4 of ($rust*)
            and $unref 
            and $susurl
        )
     
 }