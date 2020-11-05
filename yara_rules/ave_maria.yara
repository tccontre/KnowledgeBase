 import "pe"

rule ave_maria_loader {
    meta:
        author =  "tcontre"
        description = "detecting ave_maria_loader"
        date =  "2020-02-26"
        sha256 = "79c27360ee54bbd7362e7c75aac2bdd6b3dc3c8926e20ef35c07ca91807d993f"

    strings:
        $mz = { 4d 5a }
        $s1 = "Delphi-the best. Fuck off all the rest. Neshta 1.0 Made in Belarus." fullword
        $s2 = "Best regards 2 Tommy Salo" fullword
        $s3 = "Dziadulja Apanas" fullword
    
    condition:
        ($mz at 0) and all of ($s*)

    }



 import "pe"

rule ave_maria_malware {
    meta:
        author =  "tcontre"
        description = "detecting ave_maria"
        date =  "2020-02-26"
        sha256 = "02551ee4acf529c74c89591cca1f65cf7c80201b2a8d9ee7e6d024c30eb17840"

    strings:
        $mz = { 4d 5a }

        $a1 = "AVE_MARIA" fullword
        $s1 = "cmd.exe /C ping 1.2.3.4 -n 2 -w 1000 > Nul & Del /f /q " fullword
        $s2 = "SELECT * FROM logins" fullword
        $u1 = "Ave_Maria Stealer" fullword wide
        $u2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" fullword wide
        $u3 = "Elevation:Administrator!new:{3ad05575-8857-4850-9277-11b85bdb8e09}" fullword wide

    
    condition:
        ($mz at 0) and ($a1) and 1 of ($s*) and 1 of ($u*)

    }


 
