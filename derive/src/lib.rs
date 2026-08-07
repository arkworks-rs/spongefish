#![cfg_attr(docsrs, feature(doc_cfg))]

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
                        // Sized up front from the struct's own width. That is only a
                        // hint — a field whose encoding is wider or narrower than
                        // its in-memory size just makes the vector grow or over-
                        // reserve — but for the fixed-width codecs that carry
                        // prover messages it is exact, which turns several
                        // reallocations per message into one allocation.
                        let mut output = ::spongefish::__private::Vec::with_capacity(
                            ::core::mem::size_of::<Self>(),
                        );
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

/// The compile-time width reserved for a field inside the derived `Repr`.
///
/// `Decoding` exposes no associated constant for the length of its `Repr`, and
/// `AsMut::as_mut(..).len()` — the width the sponge actually fills — is not a
/// const expression, so the buffer size must be spelled with `size_of`. The
/// generated `decode` checks at run time that the two agree (see
/// [`decode_field_expr`]).
fn field_repr_size(field_type: &Type) -> TokenStream2 {
    quote! {
        ::core::mem::size_of::<<#field_type as ::spongefish::Decoding<[u8]>>::Repr>()
    }
}

/// Decodes one field out of `bytes`, advancing the shared `offset` cursor.
///
/// The width comes from `AsMut::<[u8]>::as_mut(..).len()`, the single source of
/// truth for how many bytes the sponge fills. The bounds check turns a `Repr`
/// whose slice length disagrees with its `size_of` into a loud panic instead of
/// a silent mis-slice.
fn decode_field_expr(field_type: &Type) -> TokenStream2 {
    quote! {
        {
            let mut field_buf = <#field_type as ::spongefish::Decoding<[u8]>>::Repr::default();
            let field_size = ::core::convert::AsMut::<[u8]>::as_mut(&mut field_buf).len();
            let start = offset;
            let end = start + field_size;
            assert!(
                end <= bytes.len(),
                "`Decoding` derive: field representation is wider than the derived buffer; \
                 `Repr` must satisfy `size_of::<Repr>() == Repr::default().as_mut().len()`"
            );
            ::core::convert::AsMut::<[u8]>::as_mut(&mut field_buf)
                .copy_from_slice(&bytes[start..end]);
            offset = end;
            <#field_type as ::spongefish::Decoding<[u8]>>::decode(field_buf)
        }
    }
}

fn generate_decoding_impl(input: &DeriveInput) -> TokenStream2 {
    let name = &input.ident;

    let decoding_impl = match &input.data {
        Data::Struct(data) => {
            let mut decoding_bounds = Vec::new();
            let mut size_components = vec![];
            let constructor = match &data.fields {
                Fields::Named(fields) => {
                    let mut field_decodings = vec![];

                    for field in fields.named.iter() {
                        let field_name = &field.ident;
                        if has_skip_attribute(&field.attrs) {
                            field_decodings.push(quote! {
                                #field_name: Default::default(),
                            });
                            continue;
                        }

                        let field_type = &field.ty;
                        decoding_bounds.push(field_type.clone());
                        size_components.push(field_repr_size(field_type));

                        let decode_field = decode_field_expr(field_type);
                        field_decodings.push(quote! {
                            #field_name: #decode_field,
                        });
                    }

                    quote! {
                        Self {
                            #(#field_decodings)*
                        }
                    }
                }
                Fields::Unnamed(fields) => {
                    let mut field_decodings = vec![];

                    for field in fields.unnamed.iter() {
                        if has_skip_attribute(&field.attrs) {
                            field_decodings.push(quote! {
                                Default::default(),
                            });
                            continue;
                        }

                        let field_type = &field.ty;
                        decoding_bounds.push(field_type.clone());
                        size_components.push(field_repr_size(field_type));

                        let decode_field = decode_field_expr(field_type);
                        field_decodings.push(quote! {
                            #decode_field,
                        });
                    }

                    quote! {
                        Self(#(#field_decodings)*)
                    }
                }
                Fields::Unit => quote!(Self),
            };

            let size_calc = if size_components.is_empty() {
                quote!(0usize)
            } else {
                quote!(#(#size_components)+*)
            };

            // Fields are decoded in declaration order from a single `offset`
            // cursor, so the offsets and the buffer size can never drift apart
            // silently: the final check pins the total to the buffer length.
            let decode_body = if size_components.is_empty() {
                quote! {
                    let _ = buf;
                    #constructor
                }
            } else {
                quote! {
                    let bytes = *buf.as_ref();
                    let mut offset = 0usize;
                    let value = #constructor;
                    assert_eq!(
                        offset,
                        bytes.len(),
                        "`Decoding` derive: field representations do not cover the derived buffer; \
                         every `Repr` must satisfy `size_of::<Repr>() == Repr::default().as_mut().len()`"
                    );
                    value
                }
            };

            let bound = quote!(::spongefish::Decoding<[u8]>);
            let generics =
                add_trait_bounds_for_fields(input.generics.clone(), &decoding_bounds, &bound);
            let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

            quote! {
                impl #impl_generics ::spongefish::Decoding<[u8]> for #name #ty_generics #where_clause {
                    type Repr = ::spongefish::ByteArray<{ #size_calc }>;

                    fn decode(buf: Self::Repr) -> Self {
                        #decode_body
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
                                #field_name: <#field_type as ::spongefish::NargDeserialize>::deserialize_from_narg(reader)?,
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
                                <#field_type as ::spongefish::NargDeserialize>::deserialize_from_narg(reader)?,
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
                    fn deserialize_from_narg(
                        reader: &mut ::spongefish::NargReader<'_>,
                    ) -> ::spongefish::VerificationResult<Self> {
                        // A unit struct, or one whose every field is skipped,
                        // reads nothing at all.
                        let _ = &reader;
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
/// Fields marked with `#[spongefish(skip)]` are omitted from the encoding.
/// Any other `#[spongefish(..)]` form is a compile error.
///
/// # Safety
///
/// A skipped field is not bound by the Fiat-Shamir transformation: it never
/// reaches the sponge and never reaches the NARG string, so the verifier
/// neither sees it nor commits to it. Skip only values that are recomputable,
/// or genuinely irrelevant to the statement being proven.
///
/// Skipping *every* field leaves a zero-length encoding, which is not
/// injective: all values of the struct then encode identically, and a prover
/// message of that type contributes nothing to the transcript. That is
/// well-defined but almost never intended — it is meaningful only for a type
/// with a single inhabitant, where the constant encoding is trivially
/// injective.
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

/// Derive [`Unit`](https://docs.rs/spongefish/latest/spongefish/trait.Unit.html) for structs.
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
/// ```
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

/// Helper function to check if a field has the `#[spongefish(skip)]` attribute.
///
/// # Panics
///
/// Panics — that is, fails the compilation of the deriving crate — on any
/// `#[spongefish(..)]` that is not exactly `skip`.
///
/// Dropping a field from the transcript is a security-relevant act: the field
/// stops being bound by the Fiat-Shamir transformation. It must therefore be
/// spelled out, never inferred from an attribute that failed to parse. Taking
/// `parse_nested_meta(..).is_ok()` as "skip" did the opposite: `#[spongefish()]`
/// parses zero nested metas and returns `Ok`, so an attribute that says nothing
/// silently removed the field from the encoding, the decoding and the NARG
/// string. A misspelling like `#[spongefish(skpi)]` was silently ignored in the
/// other direction. Both are now compile errors.
fn has_skip_attribute(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("spongefish") {
            return false;
        }

        let mut skip = false;
        if let Err(error) = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("skip") {
                skip = true;
                Ok(())
            } else {
                Err(meta.error("unknown `spongefish` option; expected `skip`"))
            }
        }) {
            panic!("{error}");
        }

        assert!(
            skip,
            "empty `#[spongefish(..)]`: write `#[spongefish(skip)]` to leave the \
             field out of the transcript, or remove the attribute"
        );
        skip
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
