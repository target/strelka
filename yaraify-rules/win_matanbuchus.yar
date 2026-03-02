import "pe"

rule win_matanbuchus : loader 
{
  meta:
    description =               "Detects Matanbuchus MaaS loader and core"
    author =                    "andretavare5"
    org =                       "BitSight"
    date =                      "2022-07-15"
    yarahub_author_twitter =    "@andretavare5"
    yarahub_reference_link =    "https://research.openanalysis.net/matanbuchus/loader/yara/triage/dumpulator/emulation/2022/06/19/matanbuchus-triage.html"
    yarahub_malpedia_family =   "win.matanbuchus"
    yarahub_uuid =              "0857d7bd-4d9c-478b-a11c-e80fbf948c74"
    yarahub_license =           "CC BY-NC-SA 4.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp =  "TLP:WHITE"
    yarahub_reference_md5 =     "8fc15b030254c0d49f18d06c696d6986"

  strings:
    $fowler_noll_vo_hash = {C5 9D 1C 81 [1-100] 93 01 00 01}

    // encrypted stack string of size 65 (ex: b64 alphabet + \x00)
    $x1 = /\xC7\x45.\x41\x00\x00\x00(\xC6\x45..){65}/  
    // C7 45 F8 0A 00 00 00     mov  DWORD PTR  [ebp+var_8], 65 ; str size
    // C6 45 F0 22              mov  BYTE PTR   [ebp+var_10], 22h  ; 65 movs
    
    // encrypted stack string of size >= 10 and last encrypted byte is 1
    $x2 = /\xC7\x45..\x00\x00\x00(\xC6\x45..){10,}\xC6\x45.\x01/

  condition:
    uint16(0) == 0x5A4D and // MZ
    pe.characteristics & pe.DLL and 
    filesize < 1MB and 
    $fowler_noll_vo_hash and 
    any of ($x*)
}