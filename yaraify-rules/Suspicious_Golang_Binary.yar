import "pe"

rule Suspicious_Golang_Binary
{
  meta:
    description = "Triage: Golang-compiled binary with suspicious OS/persistence/network strings (not family-specific)"
    author = "Tim Machac"
    confidence = "low_to_medium"
    version = "1.0"
    warning = "May hit admin tools; tune/allowlist"
    date = "2025-12-15"
    yarahub_reference_md5 = "87b388da9878e87988c7d89d5cb9c948"
    yarahub_uuid = "bcbf8783-19ef-44f2-abd2-db9d22c900df"
    yarahub_license = "CC0 1.0"
    yarahub_rule_matching_tlp = "TLP:WHITE"
    yarahub_rule_sharing_tlp = "TLP:WHITE"

  strings:
    // Go indicators (keep a subset here so the rule is standalone)
    $go_buildid = "Go build ID:" ascii
    $rt1 = "runtime.main" ascii
    $rt2 = "runtime.morestack" ascii
    $sym1 = "go.itab." ascii
    $pclntab = "pclntab" ascii
    $moddata = "moduledata" ascii

    // OS execution / LOLBins (Windows + *nix)
    $cmd1 = "cmd.exe /c" ascii
    $cmd2 = "powershell" ascii
    $cmd3 = "rundll32" ascii
    $cmd4 = "wmic " ascii
    $cmd5 = "schtasks" ascii
    $cmd6 = "reg add" ascii
    $cmd7 = "sc create" ascii
    $cmd8 = "/bin/sh" ascii
    $cmd9 = "bash -c" ascii
    $cmd10 = "curl " ascii
    $cmd11 = "wget " ascii

    $cmd12 = "UPX" ascii
    $cmd13 = "GetProcAddress" ascii
    $cmd14 = "VirtualAlloc" ascii
    $cmd15 = "WSAGetOverlappedResult" ascii
    $cmd16 = "timeEndPeriod" ascii

    // Network / exfil-ish HTTP markers
    $http1 = "User-Agent:" ascii
    $http2 = "Authorization: Bearer" ascii
    $http3 = "multipart/form-data" ascii
    $http4 = "POST /" ascii
    $http5 = "GET /" ascii
    $http6 = "Content-Type:" ascii

    // Persistence-ish paths/keywords (light-touch)
    $pers1 = "Microsoft\\Windows\\CurrentVersion\\Run" ascii
    $pers2 = "\\AppData\\Roaming\\" ascii
    $pers3 = "/etc/cron" ascii
    $pers4 = ".ssh/authorized_keys" ascii

  condition:
    // Must look like Go
    ( $go_buildid or (2 of ($rt*) and 1 of ($sym1,$pclntab,$moddata)) or ( $pclntab and $moddata ) )
    and
    // Plus suspicious signals
    ( 2 of ($cmd*) or 3 of ($http*) or 1 of ($pers*) )
}

