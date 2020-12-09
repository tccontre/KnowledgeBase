import "pe"

rule formbook_loader_crypter {
    meta:
        author =  "tcontre"
        description = "detecting formbook-loader-crypter malware"
        date =  "2020-11-05"
        sha256 = "ac2e9615b368e00fb4bf4d5180bbfc0d6fb7bbce3fa1af603d346d7a8f2450e5"

    strings:
        $mz = { 4d 5a }
 
        $dec = { 03 CE 8A 03 88 45 F9 8B C6 51 B9 03 00 00 00 33 D2 F7 F1 59 85 D2 75 14 8A 45 F9 32 45 FA 88 01 8A 55 FB 8B C1 E8 39 01 00 00 EB 05 8A 45 F9 88}
        $rc4_key = {12 2D 13 EF 23 E2 7F 4B 70 19 C7 F0 4B 68 75 50}
     
    condition:
        ($mz at 0) and ($dec ) or ($rc4_key)
 
    }
    
rule formbook_crypter {
    meta:
        author =  "tcontre"
        description = "detecting formbook-crypter malware"
        date =  "2020-11-05"
        sha256 = "5d7eba73b4d29ee17529511bb8b0745e658bf2adfcae57bdfa8d0870f4732a18"

    strings:
        $mz = { 4d 5a }
 
        $shell = { 4D 5A 45 52 E8 00 00 00 00 58 83 E8 09 8B C8 83 C0 3C 8B 00 03 C1 83 C0 28 03 08 FF E1 90 00 00}
	$opcode_check = {8B 4D FC 8A 04 39 03 CF 88 45 F4 8D 50 C0 80 FA 1F 77 18 6A 01 51 8D 04 1E 50 E8 ?? ?? ?? ?? 46 83 C4 0C FF 45 FC 89 75 F8 EB 25 2C 70 3C 0F 77 }
     
    condition:
        ($mz at 0) and ($shell at 0) or ($opcode_check)
 
    }
    
    
    
