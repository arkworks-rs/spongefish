use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{parse_macro_input, parse_quote, Data, DeriveInput, Fields, Type};

fn generate_encoding_impl(input: &DeriveInput) -> TokenStream2 {
    let name = &input.ident;

    let encoding_impl = match &input.data {
        Data::Struct(data) => {
            let mut encoding_bounds = Vec::new();
            let field_encodings = match &data.fields {
                Fields::Named(fields) => fields
                    .named
                    .iter()
                    .filter_map(|f| {
                        if has_skip_attribute(&f.attrs) {
                            return None;
                        }
                        let field_name = &f.ident;
                        encoding_bounds.push(f.ty.clone());
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
                        encoding_bounds.push(f.ty.clone());
                        Some(quote! {
                            output.extend_from_slice(self.#index.encode().as_ref());
                        })
                    })
                    .collect::<Vec<_>>(),
                Fields::Unit => vec![],
            };

            let bound = quote!(::spongefish::Encoding<[u8]>);
            let generics =
                add_trait_bounds_for_fields(input.generics.clone(), &encoding_bounds, &bound);
            let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

            quote! {
                impl #impl_generics ::spongefish::Encoding<[u8]> for #name #ty_generics #where_clause {
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

    encoding_impl
}

fn generate_decoding_impl(input: &DeriveInput) -> TokenStream2 {
    let name = &input.ident;

    let decoding_impl = match &input.data {
        Data::Struct(data) => {
            let mut decoding_bounds = Vec::new();
            let (size_calc, field_decodings) = match &data.fields {
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
                        decoding_bounds.push(field_type.clone());

                        size_components.push(quote! {
                            ::core::mem::size_of::<<#field_type as spongefish::Decoding<[u8]>>::Repr>()
                        });

                        let current_offset = offset.clone();
                        field_decodings.push(quote! {
                            #field_name: {
                                let field_size = ::core::mem::size_of::<<#field_type as spongefish::Decoding<[u8]>>::Repr>();
                                let start = #current_offset;
                                let end = start + field_size;
                                let mut field_buf = <#field_type as spongefish::Decoding<[u8]>>::Repr::default();
                                field_buf.as_mut().copy_from_slice(&buf.as_ref()[start..end]);
                                <#field_type as spongefish::Decoding<[u8]>>::decode(field_buf)
                            },
                        });

                        offset = quote! {
                            #offset + <#field_type as spongefish::Decoding<[u8]>>::Repr::default().as_mut().len()
                        };
                    }

                    let size_calc = if size_components.is_empty() {
                        quote!(0usize)
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

                    for field in fields.unnamed.iter() {
                        if has_skip_attribute(&field.attrs) {
                            field_decodings.push(quote! {
                                Default::default(),
                            });
                            continue;
                        }

                        let field_type = &field.ty;
                        decoding_bounds.push(field_type.clone());

                        size_components.push(quote! {
                            ::core::mem::size_of::<<#field_type as spongefish::Decoding<[u8]>>::Repr>()
                        });

                        let current_offset = offset.clone();
                        field_decodings.push(quote! {
                            {
                                let field_size = ::core::mem::size_of::<<#field_type as spongefish::Decoding<[u8]>>::Repr>();
                                let start = #current_offset;
                                let end = start + field_size;
                                let mut field_buf = <#field_type as spongefish::Decoding<[u8]>>::Repr::default();
                                field_buf.as_mut().copy_from_slice(&buf.as_ref()[start..end]);
                                <#field_type as spongefish::Decoding<[u8]>>::decode(field_buf)
                            },
                        });

                        offset = quote! {
                            #offset + <#field_type as spongefish::Decoding<[u8]>>::Repr::default().as_mut().len()
                        };
                    }

                    let size_calc = if size_components.is_empty() {
                        quote!(0usize)
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
                Fields::Unit => (quote!(0usize), quote!(Self)),
            };

            let bound = quote!(::spongefish::Decoding<[u8]>);
            let generics =
                add_trait_bounds_for_fields(input.generics.clone(), &decoding_bounds, &bound);
            let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

            quote! {
                impl #impl_generics ::spongefish::Decoding<[u8]> for #name #ty_generics #where_clause {
                    type Repr = spongefish::ByteArray<{ #size_calc }>;

                    fn decode(buf: Self::Repr) -> Self {
                        #field_decodings
                    }
                }
            }
        }
        _ => panic!("Decoding can only be derived for structs"),
    };

    decoding_impl
}

fn generate_narg_deserialize_impl(input: &DeriveInput) -> TokenStream2 {
    let name = &input.ident;

    let deserialize_impl = match &input.data {
        Data::Struct(data) => {
            let mut deserialize_bounds = Vec::new();
            let field_deserializations = match &data.fields {
                Fields::Named(fields) => {
                    let field_inits = fields.named.iter().map(|f| {
                        let field_name = &f.ident;
                        let field_type = &f.ty;

                        if has_skip_attribute(&f.attrs) {
                            quote! {
                                #field_name: Default::default(),
                            }
                        } else {
                            deserialize_bounds.push(field_type.clone());
                            quote! {
                                #field_name: <#field_type as spongefish::NargDeserialize>::deserialize_from_narg(buf)?,
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
                            deserialize_bounds.push(field_type.clone());
                            quote! {
                                <#field_type as spongefish::NargDeserialize>::deserialize_from_narg(buf)?,
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

            let bound = quote!(::spongefish::NargDeserialize);
            let generics =
                add_trait_bounds_for_fields(input.generics.clone(), &deserialize_bounds, &bound);
            let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

            quote! {
                impl #impl_generics ::spongefish::NargDeserialize for #name #ty_generics #where_clause {
                    fn deserialize_from_narg(buf: &mut &[u8]) -> spongefish::VerificationResult<Self> {
                        #field_deserializations
                    }
                }
            }
        }
        _ => panic!("NargDeserialize can only be derived for structs"),
    };

    deserialize_impl
}

/// Derive [`Encoding`](https://docs.rs/spongefish/latest/spongefish/trait.Encoding.html) for structs.
///
/// Skipped fields fall back to `Default`.
///
/// ```
/// use spongefish::Encoding;
/// # use spongefish_derive::Encoding;
///
/// #[derive(Encoding)]
/// struct Rgb {
///     r: u8,
///     g: u8,
///     b: u8,
/// }
///
/// let colors = Rgb { r: 1, g: 2, b: 3 };
/// let data = colors.encode();
/// assert_eq!(data.as_ref(), [1, 2, 3]);
///
/// ```
#[proc_macro_derive(Encoding, attributes(spongefish))]
pub fn derive_encoding(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    TokenStream::from(generate_encoding_impl(&input))
}

/// Derive macro for the [`Decoding`](https://docs.rs/spongefish/latest/spongefish/trait.Decoding.html) trait.
///
/// Generates an implementation that decodes struct fields sequentially from a fixed-size buffer.
/// Fields can be skipped using `#[spongefish(skip)]`.
#[proc_macro_derive(Decoding, attributes(spongefish))]
pub fn derive_decoding(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    TokenStream::from(generate_decoding_impl(&input))
}

/// Derive macro for the [`NargDeserialize`](https://docs.rs/spongefish/latest/spongefish/trait.NargDeserialize.html) trait.
///
/// Generates an implementation that deserializes struct fields sequentially from a byte buffer.
/// Fields can be skipped using `#[spongefish(skip)]`.
#[proc_macro_derive(NargDeserialize, attributes(spongefish))]
pub fn derive_narg_deserialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    TokenStream::from(generate_narg_deserialize_impl(&input))
}

/// Derive macro that generates [`Encoding`](https://docs.rs/spongefish/latest/spongefish/trait.Encoding.html),
/// [`Decoding`](https://docs.rs/spongefish/latest/spongefish/trait.Decoding.html), and
/// [`NargDeserialize`](https://docs.rs/spongefish/latest/spongefish/trait.NargDeserialize.html) in one go.
#[proc_macro_derive(Codec, attributes(spongefish))]
pub fn derive_codec(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let encoding = generate_encoding_impl(&input);
    let decoding = generate_decoding_impl(&input);
    let deserialize = generate_narg_deserialize_impl(&input);

    TokenStream::from(quote! {
        #encoding
        #decoding
        #deserialize
    })
}

/// Derive [`Unit`]s for structs.
///
/// ```
/// use spongefish::Unit;
/// # use spongefish_derive::Unit;
///
/// #[derive(Clone, Unit)]
/// struct Rgb {
///     r: u8,
///     g: u8,
///     b: u8,
/// }
///
/// assert_eq!((Rgb::ZERO.r, Rgb::ZERO.g, Rgb::ZERO.b), (0, 0, 0));
///
/// ```
///
/// [Unit]: https://docs.rs/spongefish/latest/spongefish/trait.Unit.html
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

fn add_trait_bounds_for_fields(
    mut generics: syn::Generics,
    field_types: &[Type],
    trait_bound: &TokenStream2,
) -> syn::Generics {
    if field_types.is_empty() {
        return generics;
    }

    let where_clause = generics.make_where_clause();
    for ty in field_types {
        where_clause
            .predicates
            .push(parse_quote!(#ty: #trait_bound));
    }

    generics
}
