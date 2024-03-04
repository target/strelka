


rule test
// This rule verifies the scanYara scanner works. Add rules here for quickstart scanning.
{
  condition:
    true
}

rule hex_extraction_test
// This rule verifies the ScanYara scanner works for hex extraction against the text fixture, "test.txt"
{
    meta:
        StrelkaHexDump = true

    strings:
        $match_str = "Venenatis tellus in metus vulputate."
    condition:
        $match_str
}

rule meta_test
// This rule verifies the ScanYara scanner works for meta categories
{
    meta:
        author = "John Doe"
        scope = "detection"

    strings:
        $match_str = "Lorem ipsum dolor sit amet"
    condition:
        $match_str
}