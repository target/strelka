import "dotnet"
import "pe"
import "math"

rule SUSP_NET_Cassandra_Protector_Feb_11 : EXE NET { 
meta:
  description = "This rule detects samples built with Cassandra."
  author      = "Utku Corbaci / Malwation"
  date        = "2025-02-11"
  sharing     = "TLP:CLEAR"
  tlp         = "WHITE"
  tags        = "windows,exe,dotnet,suspicious,protector"
  sample      = "0cb819d32cb3a2f218c5a17c02bb8c06935e926ebacf1e40a746b01e960c68e4"
  reference   = "https://www.malwation.com/blog/technical-analysis-of-phishing-campaigns-targeting-the-defense-industry-delivering-snake-keylogger"
  os          = "Windows"
  category    = "Suspicious"
  yarahub_reference_md5 = "62148599ed6d8c875296c07631ffef53"
  yarahub_author_twitter = "@rhotav"
  yarahub_author_email = "utku@rhotav.com"
  yarahub_reference_link = "https://www.malwation.com/blog/technical-analysis-of-phishing-campaigns-targeting-the-defense-industry-delivering-snake-keylogger"
  yarahub_uuid = "a8d137b0-dfb2-49d1-961e-2b95e0a5eead"
  yarahub_license = "CC0 1.0"
  yarahub_rule_matching_tlp = "TLP:WHITE"
  yarahub_rule_sharing_tlp = "TLP:WHITE"

strings:
  $lib1 = "System.Drawing.Bitmap" ascii
  $lib2 = "QSystem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" ascii
  $lib3 = "System.Resources.ResourceReader" ascii
  $lib4 = "System.Reflection" ascii

  $func1 = {28 ?? ?? ?? ?? 02 7B ?? ?? ?? ?? 0A 19 ?? ?? ?? ?? ?? 25 16 ?? ?? ?? ?? ?? A2 25 17 ?? ?? ?? ?? ?? A2 25 18 ?? ?? ?? ?? ?? A2 0B 06 07 0C 08 28 ?? ?? ?? ??}

condition: 
   dotnet.is_dotnet
   and filesize < 2MB
   and dotnet.number_of_resources > 1
   and for any i in (0..pe.number_of_sections - 1): (
		(math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) > 7.7 and
		(pe.sections[i].name == ".text" or pe.sections[i].name == ".rsrc"))
    )
   and (all of ($lib*))
   and ($func1)
}