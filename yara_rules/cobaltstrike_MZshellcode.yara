  import "pe"

rule unpack_CobaltStrike_beacon_dll_ {
    meta:
        author =  "tcontre"
        description = "detecting Cobaltstrike malware"
        date =  "2019-11-05"
        sha256 = "31d9bde8825cad11a6072fc2b8f320e2686966232b7471fe2fb9ea2ca2873fbd"

    strings:
        $mz = { 4d 5a }
 
        $shell = { 4D 5A E8 00 00 00 00 5B 89 DF 52 45 55 89 E5 81 C3 55 91 00 00 FF D3 }
        $code2 = { 64 A1 30 00 00 00 89 45 C0 8B 45 C0 8B 40 0C 89 }
        $code3 = { 8B 45 8C C1 C8 0D 89 45 8C 8B 45 88 0F BE 00 03}
        $s1 = "cdn.%x%x.%s" fullword
        $s2 = "¦www6.%x%x.%s" fullword
        $s3 = "%s.2%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x.%x%x.%s" fullword
     
    condition:
        ($mz at 0) and ($shell at 0) or 2 of ($code*) and 1 of ($s*)
 
    }
