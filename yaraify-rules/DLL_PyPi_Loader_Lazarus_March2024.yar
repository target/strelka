import "pe"

rule DLL_PyPi_Loader_Lazarus_March2024 {
    meta:
        Description = "Detects the Loader component of the Malicious PyPi Packages distributed by Lazarus Group based on PDB Paths"
        author = "Yashraj Solanki - Cyber Threat Intelligence Analyst at Bridewell"
        Reference = "https://blogs.jpcert.or.jp/en/2024/02/lazarus_pypi.html"
        Hash = "01c5836655c6a4212676c78ec96c0ac6b778a411e61a2da1f545eba8f784e980"
        date = "2024-03-01"
        yarahub_author_twitter = "@RustyNoob619"
        yarahub_reference_md5 = "a6e7c231a699d4efe85080ce5fb36dfb"
        yarahub_uuid = "c8d4f9db-44da-440d-b110-6d696e9d7839"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    condition:
        for all export in pe.export_details:
        (export.name startswith "CalculateSum")
        or (pe.pdb_path == "F:\\workspace\\CBG\\Loader\\npmLoaderDll\\x64\\Release\\npmLoaderDll.pdb"
        or pe.pdb_path == "F:\\workspace\\CBG\\npmLoaderDll\\x64\\Release\\npmLoaderDll.pdb"
        or pe.pdb_path == "D:\\workspace\\CBG\\Windows\\Loader\\npmLoaderDll\\x64\\Release\\npmLoaderDll.pdb"
        or pe.pdb_path == "F:\\workspace\\CBG\\Loader\\publicLoaderFirst\\x64\\Release\\publicLoaderFirst.pdb")
       
 }




 

 