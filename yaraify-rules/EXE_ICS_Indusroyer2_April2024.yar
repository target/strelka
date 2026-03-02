import "pe"

rule EXE_ICS_Indusroyer2_April2024 {
    meta:
        Description = "Detects Industroyer2 ICS malware targeting IEC-104 protocol"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://sectrio.com/blog/analysis-of-ot-cyberattacks-and-malwares/"
        File_Hash = "d69665f56ddef7ad4e71971f06432e59f1510a7194386e5f0e8926aea7b88e00"
        date = "2024-04-09"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "7c05da2e4612fca213430b6c93e76b06"
        yarahub_uuid = "f35815fe-648c-435a-9614-3a4773fe6d32"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        malpedia_family = "win.industroyer2"
        
    strings:
        //         --------------------IEC-104 Config--------------------
        $config1 = {00 [2-5] 00 2e 00 [2-5] 00 2e 00 [2-5] 00 2e [2-5] 00  // Target IP Address, 10.82.40.105
                   20 00 32 00 34 00 30 00 34 00 20 00                    //  Target Port, 2404
                   ?? 00 20 00                                           //   Common Address of ASDU, set to default which is 3
                   (30 | 31) 00 20 00                                   //    Operational Mode, Boolean value set to 0 thereby skipping IOA ranges
                   31 00 20 00                                         //     Extended Config to use 9 Extra Tokens 
                   31 00 20 00}                                       //      Boolean Flag set to 1 due to Extended Config Usage  
                                 
        //         ---Extended Config---
        $config2 = {2e 00 65 00 78 00 65                            // Target Executable, checking for a .exe file extension 
                   00 20 00 31 00 20 00                            //  Rename Executable Flag, set to 1
                   22 00 (43 | 44 | 45 | 46) 00 3a 00 5c 00       //   Target Executable Folder Location, set to D Drive
                   }

        //         --Extended Config cont--
        $config3 = {22 00 20 00 [1-2] 00                       // Interaction Delay Sleep Time, set to 0
                    20 00 [1-2] 00 20 00                      //  Sleep Time, set to 1 second
                    30 00 20 00                              //   Special Priority set to 0
                    30 00 20 00                             //    Special Sleep Time set to 0
                    31 00 20 00                            //     Boolean Flag set to True
                    (30 | 31) 00 20 00                    //      Default IO State set to 0
                    (30 | 31) 00 20 00                   //       Inverted IO State set to 0
                    (38 | 31 00 36 |34 00 34) 00 20 00} //        IO Count set to 44
        
        $cmd1 = "Length:%u bytes" 
        $cmd2 = "Sent=x%X"
        $cmd3 = "Received=x%X"
        $cmd4 = "ASDU:%u"
        $cmd5 = "OA:%u"
        $cmd6 = "IOA:%u"
        $cmd7 = "Cause: %s (x%X)"
        $cmd8 = "Telegram type: %s (x%X)"

        $indicator1 = "10.82.40.105" wide fullword
        $indicator2 = "2404" wide fullword
        $indicator3 = "PService_PPD.exe" wide fullword
        $indicator4 = "PServiceControl.exe" fullword
        $indicator5 = "\"D:\\OIK\\DevCounter\"" wide fullword

    condition:
        (pe.imphash() == "2cf6ff919d8af9170b36d01b351744f3"
        
        or (pe.imports("KERNEL32.dll","CreateToolhelp32Snapshot")
        and pe.imports("KERNEL32.dll","Process32First")
        and pe.imports("KERNEL32.dll","Process32Next")
        and pe.imports("KERNEL32.dll","InterlockedCompareExchange")
        and pe.imports("KERNEL32.dll","SetWaitableTimer")
        and pe.imports("WS2_32.dll","htons")
        and pe.imports("WS2_32.dll","ioctlsocket")
        and pe.imports("SHELL32.dll","CommandLineToArgvW")
        and pe.imports("OLEAUT32.dll","VarDateFromStr")
        and pe.imports("OLEAUT32.dll","VariantTimeToSystemTime")
        and pe.imports("SHLWAPI.dll","StrToIntA")
        and pe.imports("SHLWAPI.dll","wnsprintfW")
        and pe.imports("SHLWAPI.dll","wvnsprintfA")))

        and 3 of ($cmd*)
        and (all of ($config*)
        or  2 of ($indicator*))

        and filesize < 100KB
        
 }










