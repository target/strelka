import "pe"

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