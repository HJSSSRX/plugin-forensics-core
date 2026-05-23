
rule PE_Executable {
    meta:
        description = "Detect PE executables"
        author = "ForHacker"
    strings:
        $mz = {4D 5A}
        $pe = {50 45 00 00}
    condition:
        $mz at 0 and $pe
}

rule Suspicious_PowerShell {
    meta:
        description = "Detect PowerShell download cradle and encoded commands"
    strings:
        $dc = "DownloadString" nocase
        $wc = "WebClient" nocase
        $enc = "-enc" nocase ascii wide
        $ec = "-EncodedCommand" nocase
        $iex1 = "IEX(" nocase
        $iex2 = "Invoke-Expression" nocase
    condition:
        2 of them
}

rule Suspicious_URLs {
    meta:
        description = "Detect suspicious URLs and domains"
    strings:
        $paste = "pastebin.com" nocase
        $disc = "discord.com/api" nocase
        $raw = "raw.githubusercontent.com" nocase
        $temp = "temp.sh" nocase
        $ngrok = "ngrok" nocase
    condition:
        any of them
}

rule Embedded_Base64 {
    meta:
        description = "Detect long base64-encoded strings (may indicate obfuscation)"
    strings:
        $b64 = /[A-Za-z0-9+\/=]{100,}/
    condition:
        $b64
}

rule Common_Malware_Strings {
    meta:
        description = "Detect common malware IOCs"
    strings:
        $c2_1 = "C2" nocase fullword
        $keylog = "keylogger" nocase
        $ransom = "ransom" nocase
        $trojan = "trojan" nocase
        $backdoor = "backdoor" nocase
        $botnet = "botnet" nocase
    condition:
        2 of them
}
