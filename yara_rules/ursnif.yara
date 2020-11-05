import "pe"

rule ursnif_crypter_win32_ {
    meta:
        author =  "tcontre"
        description = "detecting ursnif crypter"
        date =  "2019-05-26"
        sha256 = "9abfb714de8fd134faa9c99f213d300e2c3d655f1f6df401c7c96a00d600648b"

    strings:
        $mz = { 4d 5a }
    
        $code1 = { 83 48 FB FF 66 C7 40 FF 00 0A 89 48 03 66 C7 40 1F 00 0A C6 40 21 0A }
        $code2 = { 8B 35 60 45 45 00 83 C0 40 8D 50 FB 81 C6 00 08 00 00 3B D6 72 CD }
  
    condition:
        ($mz at 0) and  1 of  ($code*)
    
    }


import "pe"

rule ursnif_loader_win32_ {
    meta:
        author =  "tcontre"
        description = "detecting ursnif loader"
        date =  "2019-05-26"
        sha256 = "dc37550986164ff2b81ba0d8b6bb46a6d2f249c6052766e87cb3b88f01852649"

    strings:
        $mz = { 4d 5a }
        $bss_check = { 81 39 2E 62 73 73 75 07 39 41 04 75 02 8B D1 }
        $code1 = { 8A 4C 24 10 D3 C0 83 C7 04 33 C6 33 C3 8B F0 89 32 83 C2 04 }
        $code2 = { 33 C3 33 45 0C 83 C7 04 FF 45 FC 8B D9 8A 4D FC D3 C8 89 06 83 C6 04}
       
  
    condition:
        ($mz at 0) and  $bss_check and 1 of  ($code*)
    
    }


import "pe"

rule ursnif_dll_payload_win32_ {
    meta:
        author =  "tcontre"
        description = "detecting ursnif dll payload in memory"
        date =  "2019-05-26"

    strings:
        $sig1 = "version=%u&soft=%u&user=%08x%08x%08x%08x&server=%u&id=%u&type=%u&name=%s" fullword
    $sig2 = "rundll32 shell32.dll,ShellExec_RunDLL" fullword wide
        $sig3 = "name=\"upload_file\"; filename=\"%.4u.%lu\"" fullword
        $sig4 = "IE8RunOnceLastShown_TIMESTAMP"

  
    condition:
        3 of  ($sig*)
    
    }

