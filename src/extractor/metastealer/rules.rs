pub static RULE_SEED: &str = r#"
rule seed {
    meta:
        author = "Frondorf, Niklas"

    strings:
        $seed = {
            89 65 f0              // mov        dword ptr [ebp + local], esp
            8b c1                 // mov        eax, ecx                         
            89 85 8c fd ff ff     // mov        dword ptr [ebp + local], eax
            8b 7b 08              // mov        edi, dword ptr [ebx + param_1]
            68 ef 06 00 00        // push       0x6ef
            89 85 84 fd ff ff     // mov        dword ptr [ebp + localc], eax
            8d 85 f0 fd ff ff     // lea        eax => local, [ebp + 0xfffffdf0]
            68 ?? ?? ?? ??        // push       seed
            50                    // push       eax
            89 bd 88 fd ff ff     // mov        dword ptr [ebp + local], edi
            c7 45 fc 00 00 00 00  // mov        dword ptr [ebp + local], 0x0
            e8 ?? ?? ?? ??        // call       dga
        }

    condition:
        all of them
}"#;

pub static RULE_PARAMS: &str = r#"
rule params {
    meta: 
        author = "Frondorf, Niklas"
    strings:
        $params = {
            0f 57 c0     // XORPS      XMM0,XMM0
            81 fe ??     // CMP        ESI,0x2710
            ?? ?? ??
            0f 83 ??     // JNC        LAB_100da487
            ?? ?? ??
            8d 4e 01     // LEA        ECX,[ESI + 0x1]
            c7 45 98     // MOV        dword ptr [EBP + local_88],0x0
            00 00 00 00
            0f af 8d     // IMUL       ECX,dword ptr [EBP + local_1d4]
            4c fe ff ff
            0f af f2     // IMUL       ESI,EDX
            0f 11 45 88  // MOVUPS     xmmword ptr [EBP + local_98[0]],XMM0
            c7 45 9c     // MOV        dword ptr [EBP + local_88+0x4],0xf
            0f 00 00 00
            c6 45 88 00  // MOV        byte ptr [EBP + local_98[0]],0x0
            03 c9        // ADD        ECX,ECX
            69 f6 ??     // IMUL       ESI,ESI,0xf6
            ?? ?? ??
            89 8d 64     // MOV        dword ptr [EBP + local_1bc],ECX
            fe ff ff
            33 f1        // XOR        ESI,ECX
            c7 45 fc     // MOV        dword ptr [EBP + local_24],0x0
            00 00 00 00
            33 ff        // XOR        EDI,EDI
            c7 85 68     // MOV        dword ptr [EBP + local_1b8],0x10
            fe ff ff 
            ?? ?? ?? ??
                         //     LAB_100d99a6
            8b c6        // MOV        EAX,ESI
            33 d2        // XOR        EDX,EDX
            25 ?? ??     // AND        EAX,0x7fffffff
            ?? ??
            b9 ?? ??     // MOV        ECX,0x1a
            ?? ??
            f7 f1        // DIV        ECX
            8d 4d 88     // LEA        ECX=>local_98,[EBP + -0x78]
            80 c2 ??     // ADD        DL,0x61
            0f b6 c2     // MOVZX      EAX,DL
            50           // PUSH       EAX
            e8 ?? ??     // CALL       FUN_10119d80
            ?? ??
            8b c7        // MOV        EAX,EDI
            03 bd 64     // ADD        EDI,dword ptr [EBP + local_1bc]
            fe ff ff
            33 c6        // XOR        EAX,ESI
            83 f0 ??     // XOR        EAX,0x34
            03 f0        // ADD        ESI,EAX
            83 ad 68     // SUB        dword ptr [EBP + local_1b8],0x1
            fe ff ff 01
            75 c9        // JNZ        LAB_100d99a6
        }

    condition:
        all of them
}"#;
