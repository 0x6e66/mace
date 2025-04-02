/// Rule for getting the location of the `customer` and `tag` parameters of coper
pub static RULE_DGA: &str = r#"
rule dga {
    meta:
        author = "Frondorf, Niklas"

    strings:
        $make_dga =  {
            48 b8 6d        
            61 6b 65 
            5f 44 47 41     // mov      rax,0x4147445f656b616d ("make_DGA")
        }

    condition:
        all of them
}"#;
