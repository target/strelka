import "pe"
 
rule possible_wiper_using_mersenne
{
  meta:
    description = "Windows PE < 500 KB containing MT19937 constants and wiper-like imports"
    date = "2026-02-02"
    author = "Nicklas Keijser"
    hash1 ="60c70cdcb1e998bffed2e6e7298e1ab6bb3d90df04e437486c04e77c411cae4b"
    hash2 = "835b0d87ed2d49899ab6f9479cddb8b4e03f5aeb2365c50a51f9088dcede68d5"
    hash3 = "65099f306d27c8bcdd7ba3062c012d2471812ec5e06678096394b238210f0f7c"
    hash4 = "d1389a1ff652f8ca5576f10e9fa2bf8e8398699ddfc87ddd3e26adb201242160"
    date = "2026-02-09"
    yarahub_uuid = "419c205a-3ec3-4db1-b959-a7bd8c3b5cb8"
    yarahub_license = "CC0 1.0"
    yarahub_reference_md5 = "a727362416834fa63672b87820ff7f27"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"
  strings:
    $const = { 65 89 07 6C }
    $twist = { DF B0 08 99 }
    $mask7f = { FF FF FF 7F }
 
  condition:
    pe.is_pe and
    pe.imports("kernel32.dll", "GetLogicalDrives") and
    pe.imports("kernel32.dll", "FindFirstFileW") and
    pe.imports("kernel32.dll", "DeleteFileW") and
    pe.imports("kernel32.dll", "FindNextFileW") and
    pe.imports("kernel32.dll", "SetFileAttributesW") and
    filesize < 500KB and
    ($const and $twist and $mask7f) and
    (
      pe.number_of_signatures == 0 or
      (
        pe.number_of_signatures > 0 and
        not for any i in (0 .. pe.number_of_signatures - 1) :
          (
            pe.signatures[i].issuer matches /Microsoft/i or
            pe.signatures[i].subject matches /Microsoft/i
          )
      )
    )
}