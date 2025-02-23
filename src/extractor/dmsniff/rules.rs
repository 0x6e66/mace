pub static RULE_PRIMES: &str = r#"
rule primes {
    meta:
        author = "Frondorf, Niklas"

    strings:
        $sequence_eax = {
            (
                b8 ?? ?? ?? ??      // mov      eax, prime
                f7 e7               // mul      edi 
                |
                8d 04 bf            // lea      eax, [edi + edi * 0x4]
            )  
            89 45 ??                // mov      dword ptr [ebp + local], eax
            50                      // push     eax
            e8 ?? ?? ?? ??          // call     halve_until_smaller_24
        }

        $sequence_edi = {
            57                      // push     edi
            e8 ?? ?? ?? ??          // call     halve_until_smaller_24
        }

        $sequence_shift = {
            (
                d1 e6               // shl      esi, 0x1
                56                  // push     esi
                |
                d1 e7               // shl      edi, 0x1
                57                  // push     edi
            )
            e8 ?? ?? ?? ??          // call     halve_until_smaller_24
        }

    condition:
        any of them
}"#;

pub static RULE_PREFIX: &str = r#"
rule prefix {
    meta:
        author = "Frondorf, Niklas"

    strings:
        $prefix = /(\xc6\x05[\x00-\xff]{4}[^\x00]|\xc6\x05[\x00-\xff]{4}[^\x00]\xc6\x05[\x00-\xff]{4}[^\x00])/

    condition:
        all of them
}"#;

pub static RULE_COUNTER: &str = r#"
rule counter {
    meta:
        author = "Frondorf, Niklas"

    strings:
        $counter = {
            (
                b8 ?? ?? ?? ??      // mov      eax, counter_max
                3b 85 ?? ?? ?? ??   // cmp      eax, dword ptr [ebp + counter]
                0f 83 ?? ?? ?? ??   // jnc      lab
            |
                83 bd ?? ?? ?? ??   // cmp      dword ptr [ebp + counter], 0x32
                ??
                0f 86 ?? ?? ?? ??   // jbe
            )
            c7 85                   // mov      dword ptr [ebp + counter], 0x1
            ?? ?? ?? ?? 
            01 00 00 00
            e9 ?? ?? ?? ??          // jmp      lab
        }

    condition:
        all of them
}"#;

pub static RULE_TLDS: &str = r#"
rule tlds {
    meta:
        author = "Frondorf, Niklas"

    strings:
        $tds = {
            (
                73 ??               // jnc      label
            |
                76 ??               // jbe      label
            |
                eb ??               // jmp      label
            )
            68 ?? ?? ?? ??          // push     encrypted_tld
            e8 ?? ?? ?? ??          // call     decrypt_string
        }

    condition:
        all of them
}"#;

pub static RULE_KEYS: &str = r#"
rule keys {
    meta:
        author = "Frondorf, Niklas"

    strings:
        $keys = {
            (
                83 e2 ??            // and      edx, key1
            |
                b9 ?? ?? ?? ??      // mov      ecx, key1
                31 d2               // xor      edx, edx
                f7 f1               // div      ecx
            )
            0f b6 ?? ??             // movzx
            ?? ?? ?? ??
        }

    condition:
        all of them
}"#;
