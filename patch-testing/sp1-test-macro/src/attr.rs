use proc_macro2::Span;
use syn::{
    bracketed,
    parse::{Parse, ParseStream},
    punctuated::Punctuated,
    Ident, LitStr, Token,
};

#[derive(Debug)]
pub struct AttrOptions(Vec<AttrOption>);

impl AttrOptions {
    /// Add a unique option to the list of attribute options.
    ///
    /// If a duplicate option is found, an error is returned.
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

    pub fn syscalls(&self) -> Vec<Ident> {
        self.0
            .iter()
            .find_map(|o| {
                if let AttrOption::Syscalls(syscalls) = o {
                    Some(syscalls.clone())
                } else {
                    None
                }
            })
            .unwrap_or_default()
    }

    pub fn setup(&self) -> Option<&Ident> {
        self.0.iter().find_map(
            |o| {
                if let AttrOption::Setup(ident) = o {
                    Some(ident)
                } else {
                    None
                }
            },
        )
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
    Syscalls(Vec<Ident>),
    Prove,
    Gpu,
    Setup(Ident),
}

impl AttrOption {
    /// Checks if this variant of `AttrOption` matches another.
    fn matches(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
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
                let (span, option) = parse_option(&input)?;

                options.push(option, span)?;
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

fn parse_option(input: &ParseStream) -> syn::Result<(Span, AttrOption)> {
    let ident = input.parse::<Ident>()?;

    match ident.to_string().as_str() {
        "prove" => Ok((ident.span(), AttrOption::Prove)),
        "gpu" => Ok((ident.span(), AttrOption::Gpu)),
        "elf" => {
            input.parse::<Token![=]>()?;
            let lit_str = input.parse::<LitStr>()?;

            Ok((lit_str.span(), AttrOption::Elf(lit_str.value())))
        }
        "setup" => {
            input.parse::<Token![=]>()?;
            let ident = input.parse::<Ident>()?;

            Ok((ident.span(), AttrOption::Setup(ident)))
        }
        "syscalls" => {
            input.parse::<Token![=]>()?;
            let content;
            bracketed!(content in input);
            let syscalls: Punctuated<Ident, Token![,]> =
                Punctuated::parse_separated_nonempty(&content)?;
            let vec_syscalls = syscalls.into_iter().collect();

            Ok((ident.span(), AttrOption::Syscalls(vec_syscalls)))
        }
        _ => Err(syn::Error::new(ident.span(), format!("Found Unknown attribute option {ident}"))),
    }
}
