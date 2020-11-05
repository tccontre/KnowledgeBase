import "pe"

rule gandcrab_win32_downloader_unpack {
    meta:
        author =  "tccontre"
        description = "detecting gandcrab downloader"
        date =  "2018-11-08"
        sha256 = "7cb45951e8f8dd064b467dd55819c83d3d85359ef7a382c3bad9f9116282e2e4"
   
    strings:
        $mz = { 4d 5a }
       
        $s1 = "open=_\\DeviceManager.exe" fullword
        $s2 = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:25.0) Gecko/20100101 Firefox/25.0" fullword
       
        $c0 = "DisableAntiSpyware" fullword wide
        $c1 = "DisableBehaviorMonitoring" fullword wide
        $c2 = "FirewallDisableNotify" fullword wide
        $c3 = "ls\\T80870405687060" fullword
        $c4 = "Recycle.Bin" fullword wide
        $c5 = "autorun.inf" fullword wide
       
       
        $code1 = { 83 C8 20 83 F8 61 74 61 8B 45 FC 0F B7 00 83 C8 20 83 F8 62 74 53 }
        $code2 = { D1 E8 EB 07 D1 E8 35 20 83 B8 ED E2 EC AB }
                
    condition:
        ($mz at 0) and all of ($s*) and 2 of ($c*) and 1 of ($code*)
       
    }
