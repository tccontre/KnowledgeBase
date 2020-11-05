import "pe"

rule dofoil_unpack {
    meta:
        author =  "tccontre"
        description = "detecting gdofoil downloader"
        date =  "2019-08-01"
        sha256 = "7d71cc36f49c758204205d39caa6f4ee6d010ddebda8acd0a98d7ad7e306fc62"
  
    strings:
        $mz = { 4d 5a }      
      
        $code1 = { AC EB 05 CC ED 79 15 CC 30 D0 AA E2 F3}

    condition:
        ($mz at 0) and $code1
      
    }
