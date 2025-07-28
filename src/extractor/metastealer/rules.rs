pub static RULE_SEED: &str = r#"
rule seed {
    meta:
        author = "Frondorf, Niklas"

    strings:
        $seed = {
            (
                68 ?? ?? ?? ??        // push       value
                89 85 ?? ?? ?? ??     // mov        dword ptr [ebp + localc], eax
                8d 85 ?? ?? ?? ??     // lea        eax => local, [ebp + offset]
                68 ?? ?? ?? ??        // push       seed
                |
                8d 85 ?? ?? ?? ??     // lea        eax => local, [ebp + offset]
                68 ?? ?? ?? ??        // push       value
                68 ?? ?? ?? ??        // push       seed
                |
                8d 85 ?? ?? ?? ??     // lea        eax => local, [ebp + offset]
                89 85 ?? ?? ?? ??     // mov        dword ptr [ebp + localc], eax
                68 ?? ?? ?? ??        // push       value
                68 ?? ?? ?? ??        // push       seed
                |
                8d 96 ?? ?? ?? ??     // lea        edx => local, [esi + value]
                c7 86 [8]             // mov        dword ptr [esi + local], value
                68 ?? ?? ?? ??        // push       value
                68 ?? ?? ?? ??        // push       seed
                |
                c7 86 [8]             // mov        dword ptr [esi + local], value
                68 ?? ?? ?? ??        // push       value
                68 ?? ?? ?? ??        // push       seed
                |
                c7 86 [8]             // mov        dword ptr [esi + local], value
                68 ?? ?? ?? ??        // push       value
                68 ?? ?? ?? ??        // push       seed
                8d 86 ?? ?? ?? ??     // lea        eax => local, [esi + value]
            )

            (
                50                    // push       eax
                |
                52                    // push       edx
            )

            (
                89 bd ?? ?? ?? ??     // mov        dword ptr [ebp + local], edi
                c7 45 fc 00 00 00 00  // mov        dword ptr [ebp + local], 0x0
                e8 ?? ?? ?? ??        // call       dga
                |
                89 b5 ?? ?? ?? ??     // mov        dword ptr [ebp + local], esi
                89 bd ?? ?? ?? ??     // mov        dword ptr [ebp + local], edi
                c7 45 fc 00 00 00 00  // mov        dword ptr [ebp + local], 0x0
                e8 ?? ?? ?? ??        // call       dga
                |
                c5 f8 77              // vzeroupper
                e8 ?? ?? ?? ??        // call       dga
                |
                e8 ?? ?? ?? ??        // call       dga
            )
        }

    condition:
        all of them
}"#;
