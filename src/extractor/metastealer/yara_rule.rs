pub static RULE: &str = r#"
rule asdf {
    meta:
        author = "Frondorf, Niklas"

    strings:
        $sequence = {
            89 65 f0              // MOV        dword ptr [EBP + local_30],ESP
            8b c1                 // MOV        EAX,ECX                         
            89 85 8c fd ff ff     // MOV        dword ptr [EBP + local_294],EAX
            8b 7b 08              // MOV        EDI,dword ptr [EBX + param_1]
            68 ef 06 00 00        // PUSH       0x6ef
            89 85 84 fd ff ff     // MOV        dword ptr [EBP + local_29c],EAX
            8d 85 f0 fd ff ff     // LEA        EAX=>local_230,[EBP + 0xfffffdf0]
            68 ?? ?? ?? ??        // PUSH       0x1234
            50                    // PUSH       EAX 
            89 bd 88 fd ff ff     // MOV        dword ptr [EBP + local_298],EDI
            c7 45 fc 00 00 00 00  // MOV        dword ptr [EBP + local_24],0x0
            e8 ?? ?? ?? ??        // CALL       FUN_100d98d0
        }

        /*
        100d2ff2 89 65 f0        MOV        dword ptr [EBP + local_30],ESP
        100d2ff5 8b c1           MOV        EAX,ECX
        100d2ff7 89 85 8c        MOV        dword ptr [EBP + local_294],EAX
                 fd ff ff
        100d2ffd 8b 7b 08        MOV        EDI,dword ptr [EBX + param_1]
        100d3000 68 ef 06        PUSH       0x6ef
                 00 00
        100d3005 89 85 84        MOV        dword ptr [EBP + local_29c],EAX
                 fd ff ff
        100d300b 8d 85 f0        LEA        EAX=>local_230,[EBP + 0xfffffdf0]
                 fd ff ff
                             DGA_SEED
        100d3011 68 34 12        PUSH       0x1234
                 00 00
        100d3016 50              PUSH       EAX
        100d3017 89 bd 88        MOV        dword ptr [EBP + local_298],EDI
                 fd ff ff
        100d301d c7 45 fc        MOV        dword ptr [EBP + local_24],0x0
                 00 00 00 00
        100d3024 e8 a7 68        CALL       FUN_100d98d0
                 00 00
        */
    condition:
        all of them
}"#;
