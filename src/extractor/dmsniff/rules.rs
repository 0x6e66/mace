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

    condition:
        $sequence_eax or $sequence_edi
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
