/*
YARA Rule Set
Author: The DFIR Report
Date: 2021-02-22
Identifier: Bazar Drops the Anchor
Reference: https://thedfirreport.com/2021/03/08/bazar-drops-the-anchor/
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule cobalt_strike_tmp01925d3f {
	meta:
      description = "files - file ~tmp01925d3f.exe"
      author = "The DFIR Report"
      reference = "https://thedfirreport.com"
      date = "2021-02-22"
      yarahub_reference_md5 = "1c6ba04dc9808084846ac1005deb9c85"
      yarahub_uuid = "58ae3b15-154e-47e9-a24c-c8b885a4cd55"
      yarahub_license = "CC0 1.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      hash1 = "10ff83629d727df428af1f57c524e1eaddeefd608c5a317a5bfc13e2df87fb63"
      score = 80
	strings:
      $x1 = "C:\\Users\\hillary\\source\\repos\\gromyko\\Release\\gromyko.pdb" fullword ascii
      $x2 = "api-ms-win-core-synch-l1-2-0.dll" fullword wide /* reversed goodware string 'lld.0-2-1l-hcnys-eroc-niw-sm-ipa' */
      $s3 = "gromyko32.dll" fullword ascii
      $s4 = "<requestedExecutionLevel level='asInvoker' uiAccess='false'/>" fullword ascii
      $s5 = "AppPolicyGetProcessTerminationMethod" fullword ascii
      $s6 = "https://sectigo.com/CPS0" fullword ascii
      $s7 = "2http://crl.comodoca.com/AAACertificateServices.crl04" fullword ascii
      $s8 = "?http://crl.usertrust.com/USERTrustRSACertificationAuthority.crl0v" fullword ascii
      $s9 = "3http://crt.usertrust.com/USERTrustRSAAddTrustCA.crt0%" fullword ascii
      $s10 = "http://ocsp.sectigo.com0" fullword ascii
      $s11 = "2http://crl.sectigo.com/SectigoRSACodeSigningCA.crl0s" fullword ascii
      $s12 = "2http://crt.sectigo.com/SectigoRSACodeSigningCA.crt0#" fullword ascii
      $s13 = "http://www.digicert.com/CPS0" fullword ascii
      $s14 = "AppPolicyGetThreadInitializationType" fullword ascii
      $s15 = "alerajner@aol.com0" fullword ascii
      $s16 = "gromyko.inf" fullword ascii
      $s17 = "operator<=>" fullword ascii
      $s18 = "operator co_await" fullword ascii
      $s19 = "gromyko" fullword ascii
      $s20 = "api-ms-win-appmodel-runtime-l1-1-2" fullword wide
	condition:
      uint16(0) == 0x5a4d and filesize < 1000KB and
      ( pe.imphash() == "1b1b73382580c4be6fa24e8297e1849d" or ( 1 of ($x*) or 4 of them ) )
}