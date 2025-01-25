rule latrodectus_dll {
  meta:
      author = "0x0d4y"
      description = "This rule detects the Latrodectus DLL Decrypt String Algorithm."
      date = "2024-05-01"
      score = 100
      reference = "https://0x0d4y.blog/latrodectus-technical-analysis-of-the-new-icedid/"
      yarahub_reference_md5 = "277c879bba623c8829090015437e002b"
      yarahub_uuid = "9da6bcb5-382c-4c64-97c4-97d15db45cad"
      yarahub_license = "CC BY 4.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      malpedia_family = "win.unidentified_111"
    strings:
    $str_decrypt = { 48 89 54 24 10 48 89 4c 24 08 48 83 ec ?? 33 c9 e8 ?? ?? ?? ?? 48 8b 44 24 40 8b 00 89 44 24 2c 48 8b 44 24 40 0f b7 40 04 8b 4c 24 2c 33 c8 8b c1 66 89 44 24 28 48 8b 44 24 40 48 83 c0 06 48 89 44 24 40 33 c0 66 89 44 ?? ?? ?? ?? 0f b7 44 ?? ?? 66 ff c0 66 89 44 ?? ?? 0f b7 44 ?? ?? 0f b7 4c 24 28 ?? ?? 0f ?? ?? ?? ?? ?? 0f b7 44 ?? ?? 48 8b 4c 24 40 8a 04 01 88 44 24 20 0f b7 44 ?? ?? 48 8b 4c 24 40 8a 04 01 88 44 24 21 0f b6 44 24 20 0f b6 4c 24 21 8d 44 01 0a 88 44 24 21 8b 4c 24 2c ?? ?? ?? ?? ?? 89 44 24 2c 0f b7 44 ?? ?? 0f b6 4c 24 20 48 8b 54 24 48 0f b6 04 02 8d 44 08 0a 0f b7 4c ?? ?? 48 8b 54 24 48 88 04 0a 0f b6 44 24 20 0f b6 4c 24 2c 33 c1 0f b7 4c ?? ?? 48 8b 54 24 48 88 04 0a ?? ?? ?? ?? ?? 48 8b 44 24 48 48 83 c4 38 }
    condition:
        uint16(0) == 0x5a4d and
        $str_decrypt
}