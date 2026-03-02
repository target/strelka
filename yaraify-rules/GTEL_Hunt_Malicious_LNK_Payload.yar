rule GTEL_Hunt_Malicious_LNK_Payload {
    meta:
        description = "Phat hien file LNK thuc thi lenh CMD/Powershell (CV gia mao)"
        author = "GTEL Intelligence Support"
        date = "2025-12-08"
        // --- YARAify Mandatory Fields ---
        yarahub_uuid = "c54b70d7-4f0d-4ec6-9d17-cab13551835c"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "00839f128a2daa17623bf578cd7e2a85"
        // --------------------------------
        campaign = "Hanoi Thief"
        threat_type = "Initial Access"

    strings:
        $lnk_header = { 4C 00 00 00 01 14 02 00 }

        $cmd_shell = "cmd.exe" nocase
        $ps_shell  = "powershell" nocase
        $wscript   = "wscript" nocase
        $cscript   = "cscript" nocase
        $rundll    = "rundll32" nocase
        
        // 3. Network & Download Indicators
        $http  = "http" nocase
        $curl  = "curl" nocase
        $bits  = "bitsadmin" nocase
        

        $doc_fake1 = ".pdf" nocase
        $doc_fake2 = ".doc" nocase
        $doc_fake3 = ".docx" nocase
        $doc_fake4 = ".xlsx" nocase

    condition:
        $lnk_header at 0 and 
        // Phai chua it nhat 1 lenh thuc thi nguy hiem
        (1 of ($cmd_shell, $ps_shell, $wscript, $cscript, $rundll)) and
        // Va co dau hieu gia mao tai lieu
        (1 of ($doc_fake*)) and 
        // Kich thuoc file LNK thuong khong qua lon (duoi 50KB)
        filesize < 50KB
}