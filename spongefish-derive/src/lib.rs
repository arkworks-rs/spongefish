use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, parse_quote, Data, DeriveInput, Fields, Type};

/// Derive macro for the Encoding trait.
///
/// Generates an implementation that encodes struct fields sequentially.
/// Fields can be skipped using `#[spongefish(skip)]`.
#[proc_macro_derive(Encoding, attributes(spongefish))]
pub fn derive_encoding(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    let encoding_impl = match input.data {
        Data::Struct(data) => {
            let field_encodings = match data.fields {
                Fields::Named(fields) => fields
                    .named
                    .iter()
                    .enumerate()
                    .filter_map(|(_, f)| {
                        if has_skip_attribute(&f.attrs) {
                            return None;
                        }
                        let field_name = &f.ident;
                        Some(quote! {
                            output.extend_from_slice(self.#field_name.encode().as_ref());
                        })
                    })
                    .collect::<Vec<_>>(),
                Fields::Unnamed(fields) => fields
                    .unnamed
                    .iter()
                    .enumerate()
                    .filter_map(|(i, f)| {
                        if has_skip_attribute(&f.attrs) {
                            return None;
                        }
                        let index = syn::Index::from(i);
                        Some(quote! {
                            output.extend_from_slice(self.#index.encode().as_ref());
                        })
                    })
                    .collect::<Vec<_>>(),
                Fields::Unit => vec![],
            };

            quote! {
                impl spongefish::codecs::Encoding<[u8]> for #name {
                    fn encode(&self) -> impl AsRef<[u8]> {
                        let mut output = ::std::vec::Vec::new();
                        #(#field_encodings)*
                        output
                    }
                }
            }
        }
        _ => panic!("Encoding can only be derived for structs"),
    };

    TokenStream::from(encoding_impl)
}

/// Derive macro for the Decoding trait.
///
/// Generates an implementation that decodes struct fields sequentially from a fixed-size buffer.
/// Fields can be skipped using `#[spongefish(skip)]`.
#[proc_macro_derive(Decoding, attributes(spongefish))]
pub fn derive_decoding(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    let decoding_impl = match input.data {
        Data::Struct(data) => {
            // Calculate total size and generate field decodings
            let (size_calc, field_decodings) = match data.fields {
                Fields::Named(fields) => {
                    let mut offset = quote!(0usize);
                    let mut field_decodings = vec![];
                    let mut size_components = vec![];

                    for field in fields.named.iter() {
                        if has_skip_attribute(&field.attrs) {
                            let field_name = &field.ident;
                            field_decodings.push(quote! {
                                #field_name: Default::default(),
                            });
                            continue;
                        }

                        let field_name = &field.ident;
                        let field_type = &field.ty;

                        size_components.push(quote! {
                            <#field_type as spongefish::codecs::Decoding<[u8]>>::Repr::default().as_mut().len()
                        });

                        let current_offset = offset.clone();
                        field_decodings.push(quote! {
                            #field_name: {
                                let field_size = <#field_type as spongefish::codecs::Decoding<[u8]>>::Repr::default().as_mut().len();
                                let start = #current_offset;
                                let end = start + field_size;
                                let mut field_buf = <#field_type as spongefish::codecs::Decoding<[u8]>>::Repr::default();
                                field_buf.as_mut().copy_from_slice(&buf[start..end]);
                                <#field_type as spongefish::codecs::Decoding<[u8]>>::decode(field_buf)
                            },
                        });

                        offset = quote! {
                            #offset + <#field_type as spongefish::codecs::Decoding<[u8]>>::Repr::default().as_mut().len()
                        };
                    }

                    let size_calc = if size_components.is_empty() {
                        quote!(0)
                    } else {
                        quote!(#(#size_components)+*)
                    };

                    (
                        size_calc,
                        quote! {
                            Self {
                                #(#field_decodings)*
                            }
                        },
                    )
                }
                Fields::Unnamed(fields) => {
                    let mut offset = quote!(0usize);
                    let mut field_decodings = vec![];
                    let mut size_components = vec![];

                    for (_i, field) in fields.unnamed.iter().enumerate() {
                        if has_skip_attribute(&field.attrs) {
                            field_decodings.push(quote! {
                                Default::default(),
                            });
                            continue;
                        }

                        let field_type = &field.ty;

                        size_components.push(quote! {
                            <#field_type as spongefish::codecs::Decoding<[u8]>>::Repr::default().as_mut().len()
                        });

                        let current_offset = offset.clone();
                        field_decodings.push(quote! {
                            {
                                let field_size = <#field_type as spongefish::codecs::Decoding<[u8]>>::Repr::default().as_mut().len();
                                let start = #current_offset;
                                let end = start + field_size;
                                let mut field_buf = <#field_type as spongefish::codecs::Decoding<[u8]>>::Repr::default();
                                field_buf.as_mut().copy_from_slice(&buf[start..end]);
                                <#field_type as spongefish::codecs::Decoding<[u8]>>::decode(field_buf)
                            },
                        });

                        offset = quote! {
                            #offset + <#field_type as spongefish::codecs::Decoding<[u8]>>::Repr::default().as_mut().len()
                        };
                    }

                    let size_calc = if size_components.is_empty() {
                        quote!(0)
                    } else {
                        quote!(#(#size_components)+*)
                    };

                    (
                        size_calc,
                        quote! {
                            Self(#(#field_decodings)*)
                        },
                    )
                }
                Fields::Unit => (quote!(0), quote!(Self)),
            };

            quote! {
                impl spongefish::codecs::Decoding<[u8]> for #name {
                    type Repr = [u8; {
                        const SIZE: usize = #size_calc;
                        SIZE
                    }];

                    fn decode(buf: Self::Repr) -> Self {
                        #field_decodings
                    }
                }
            }
        }
        _ => panic!("Decoding can only be derived for structs"),
    };

    TokenStream::from(decoding_impl)
}

/// Derive macro for the NargDeserialize trait.
///
/// Generates an implementation that deserializes struct fields sequentially from a byte buffer.
/// Fields can be skipped using `#[spongefish(skip)]`.
#[proc_macro_derive(NargDeserialize, attributes(spongefish))]
pub fn derive_narg_deserialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    let deserialize_impl = match input.data {
        Data::Struct(data) => {
            let field_deserializations = match data.fields {
                Fields::Named(fields) => {
                    let field_inits = fields.named.iter().map(|f| {
                        let field_name = &f.ident;
                        let field_type = &f.ty;

                        if has_skip_attribute(&f.attrs) {
                            quote! {
                                #field_name: Default::default(),
                            }
                        } else {
                            quote! {
                                #field_name: <#field_type as spongefish::io::NargDeserialize>::deserialize_from(buf)?,
                            }
                        }
                    });

                    quote! {
                        Ok(Self {
                            #(#field_inits)*
                        })
                    }
                }
                Fields::Unnamed(fields) => {
                    let field_inits = fields.unnamed.iter().map(|f| {
                        let field_type = &f.ty;

                        if has_skip_attribute(&f.attrs) {
                            quote! {
                                Default::default(),
                            }
                        } else {
                            quote! {
                                <#field_type as spongefish::io::NargDeserialize>::deserialize_from(buf)?,
                            }
                        }
                    });

                    quote! {
                        Ok(Self(#(#field_inits)*))
                    }
                }
                Fields::Unit => quote! {
                    Ok(Self)
                },
            };

            quote! {
                impl spongefish::io::NargDeserialize for #name {
                    fn deserialize_from(buf: &mut &[u8]) -> spongefish::VerificationResult<Self> {
                        #field_deserializations
                    }
                }
            }
        }
        _ => panic!("NargDeserialize can only be derived for structs"),
    };

    TokenStream::from(deserialize_impl)
}

/// Derive macro for the Unit trait.
///
/// Generates an implementation whose zero element sets every field to its [`Unit::ZERO`].
#[proc_macro_derive(Unit, attributes(spongefish))]
pub fn derive_unit(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;
    let mut generics = input.generics;

    let (zero_expr, unit_bounds) = match input.data {
        Data::Struct(data) => match data.fields {
            Fields::Named(fields) => {
                let mut zero_fields = Vec::new();
                let mut unit_bounds = Vec::new();

                for field in fields.named.iter() {
                    let field_name = &field.ident;

                    if has_skip_attribute(&field.attrs) {
                        zero_fields.push(quote! {
                            #field_name: ::core::default::Default::default(),
                        });
                        continue;
                    }

                    let ty: Type = field.ty.clone();
                    unit_bounds.push(ty.clone());
                    zero_fields.push(quote! {
                        #field_name: <#ty as ::spongefish::Unit>::ZERO,
                    });
                }

                (
                    quote! {
                        Self {
                            #(#zero_fields)*
                        }
                    },
                    unit_bounds,
                )
            }
            Fields::Unnamed(fields) => {
                let mut zero_fields = Vec::new();
                let mut unit_bounds = Vec::new();

                for field in fields.unnamed.iter() {
                    if has_skip_attribute(&field.attrs) {
                        zero_fields.push(quote! {
                            ::core::default::Default::default()
                        });
                        continue;
                    }

                    let ty: Type = field.ty.clone();
                    unit_bounds.push(ty.clone());
                    zero_fields.push(quote! {
                        <#ty as ::spongefish::Unit>::ZERO
                    });
                }

                (
                    quote! {
                        Self(#(#zero_fields),*)
                    },
                    unit_bounds,
                )
            }
            Fields::Unit => (quote!(Self), Vec::new()),
        },
        _ => panic!("Unit can only be derived for structs"),
    };

    let where_clause = generics.make_where_clause();
    for ty in unit_bounds {
        where_clause
            .predicates
            .push(parse_quote!(#ty: ::spongefish::Unit));
    }

    let (impl_generics, ty_generics, where_generics) = generics.split_for_impl();

    let expanded = quote! {
        impl #impl_generics ::spongefish::Unit for #name #ty_generics #where_generics {
            const ZERO: Self = #zero_expr;
        }
    };

    TokenStream::from(expanded)
}

/// Helper function to check if a field has the #[spongefish(skip)] attribute
fn has_skip_attribute(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("spongefish") {
            return false;
        }

        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("skip") {
                Ok(())
            } else {
                Err(meta.error("expected `skip`"))
            }
        })
        .is_ok()
    })
}
