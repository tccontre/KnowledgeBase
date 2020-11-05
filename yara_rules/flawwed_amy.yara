import "pe"

rule unpack_flawed_ammy_downloader_win32_ {
    meta:
        author =  "tcontre"
        description = "detecting flawwed ammy rat downloader"
        date =  "2019-07-02"
        sha256 = "3255b1165b227c35b70908f4eed490210390281fc96913fdf96f066d019bd1c2"

    strings:
        $mz = { 4d 5a }
    
        $code1 = { 8B 45 FC C1 E0 07 8B 4D FC C1 E9 19 0B C1 }
       
        $n1 = "net user /domain" fullword
        $n2 = "net group /domain" fullword
       
        $s1 = "NuGets\\template_%x.TMPTMPZIP7" fullword
        $s2 = "wsus.exe" fullword
        $s3 = "Vmwaretrat.exe" fullword wide
    condition:
        ($mz at 0) and $code1 and 1of ($n*) and 1 of ($s*)
    
    }
