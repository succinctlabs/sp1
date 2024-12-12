use syn::{parse::{Parse, ParseStream}, Ident, LitStr, Token};
use proc_macro2::Span;

#[derive(Debug)]
pub struct AttrOptions(Vec<AttrOption>);

impl AttrOptions {
    pub fn push(&mut self, option: AttrOption, span: Span) -> syn::Result<()> {
        if !self.0.iter().any(|o| o.matches(&option)) {
            self.0.push(option);
        } else {
            return Err(syn::Error::new(span, "Duplicate attribute option"));
        }

        Ok(())
    }

    pub fn new() -> Self {
        AttrOptions(Vec::new())
    }

    pub fn gpu(&self) -> bool {
        self.0.iter().any(|o| matches!(o, AttrOption::Gpu))
    }

    pub fn prove(&self) -> bool {
        self.0.iter().any(|o| matches!(o, AttrOption::Prove))
    }

    pub fn elf_name(&self) -> Option<&str> {
        self.0.iter().find_map(|o| {
            if let AttrOption::Elf(name) = o {
                Some(name.as_str())
            } else {
                None
            }
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AttrOption {
    Elf(String),
    Prove,
    Gpu
}

impl AttrOption {
    fn matches(&self, other: &Self) -> bool {
        match (self, other) {
            (AttrOption::Elf(_), AttrOption::Elf(_)) => true,
            (AttrOption::Prove, AttrOption::Prove) => true,
            (AttrOption::Gpu, AttrOption::Gpu) => true,
            _ => false
        }
    }
}


impl Parse for AttrOptions {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.is_empty() {
            return Err(input.error("No attribute options provided, expected at least an ELF name."));
        }

        let mut options = AttrOptions::new(); 
        while !input.is_empty() {
            let lookahead = input.lookahead1();
            if lookahead.peek(Ident) {
                let ident = input.parse::<Ident>()?;
                let span = ident.span();

                if ident == "elf" {
                    input.parse::<Token![=]>()?;
                    let lit_str = input.parse::<LitStr>()?;
                    options.push(AttrOption::Elf(lit_str.value()), span)?;
                } else {
                    let option = handle_ident(&ident)?;
                    options.push(option, span)?;
                }
            } else if lookahead.peek(LitStr) {
                // handle the case where the user just passes in ELF name
                let lit_str = input.parse::<LitStr>()?;
                options.push(AttrOption::Elf(lit_str.value()), lit_str.span())?;
            } else {
                return Err(lookahead.error());
            }
            
            // We still have attributes to parse, and they should be separated by commas
            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(options)
    }
}

fn handle_ident(ident: &Ident) -> syn::Result<AttrOption> {
    match ident.to_string().as_str() {
        "prove" => Ok(AttrOption::Prove),
        "gpu" => Ok(AttrOption::Gpu),
        // handled above
        "elf" => unreachable!(),
        _ => Err(syn::Error::new(ident.span(), format!("Found Unknown attribute option {}", ident)))
    }
}
