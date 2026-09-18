#![cfg_attr(docsrs, feature(doc_cfg))]

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{parse_macro_input, parse_quote, Data, DeriveInput, Member, Result, Type};

/// One field of the deriving struct, with the member it is reached by.
///
/// [`Member`] is what lets named and tuple structs share every code path in
/// this crate. `self.#member` reads `self.field` and `self.0` alike, and braced
/// construction — `Self { #member: .. }` — builds a tuple struct as readily as
/// a named one. The field-less case falls out for free: `Self {}` constructs a
/// unit struct.
struct StructField<'a> {
    member: Member,
    ty: &'a Type,
    /// Set by `#[spongefish(skip)]`: the field is left out of every map, and
    /// filled with `Default::default()` on the way back.
    skip: bool,
}

/// The deriving struct's fields, in declaration order.
///
/// Errors if the input is not a struct, or if a field carries a malformed
/// `#[spongefish(..)]`.
fn struct_fields<'a>(input: &'a DeriveInput, derive: &str) -> Result<Vec<StructField<'a>>> {
    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new_spanned(
            &input.ident,
            format!("{derive} can only be derived for structs"),
        ));
    };

    data.fields
        .iter()
        .enumerate()
        .map(|(index, field)| {
            let member = field
                .ident
                .clone()
                .map_or_else(|| Member::Unnamed(syn::Index::from(index)), Member::Named);
            Ok(StructField {
                member,
                ty: &field.ty,
                skip: has_skip_attribute(&field.attrs)?,
            })
        })
        .collect()
}

/// The types that must be bounded for an impl to hold: every field that is
/// actually encoded or decoded, and no others.
///
/// A skipped field is untouched by the generated code, so bounding it would
/// reject types the derive can perfectly well handle.
fn bounded_types<'a>(fields: &'a [StructField<'a>]) -> Vec<&'a Type> {
    fields
        .iter()
        .filter(|field| !field.skip)
        .map(|field| field.ty)
        .collect()
}

/// Wraps `items` in an impl of `trait_path` for the deriving type, adding a
/// `#ty: #trait_path` predicate for each of `bounded`.
fn impl_block(
    input: &DeriveInput,
    trait_path: &TokenStream2,
    bounded: &[&Type],
    items: &TokenStream2,
) -> TokenStream2 {
    let name = &input.ident;
    let mut generics = input.generics.clone();

    if !bounded.is_empty() {
        let where_clause = generics.make_where_clause();
        for ty in bounded {
            where_clause.predicates.push(parse_quote!(#ty: #trait_path));
        }
    }

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    quote! {
        impl #impl_generics #trait_path for #name #ty_generics #where_clause {
            #items
        }
    }
}

/// The width of a field's `Repr`, as a constant expression.
///
/// `Decoding::Repr` is a `hybrid_array` array of size its `typenum` constant.
fn field_repr_size(field_type: &Type) -> TokenStream2 {
    quote! {
        <<<#field_type as ::spongefish::Decoding>::Repr
            as ::spongefish::hybrid_array::AssocArraySize>::Size
            as ::spongefish::hybrid_array::typenum::Unsigned>::USIZE
    }
}

/// Decodes one field out of `bytes`, advancing the shared `offset` cursor.
fn decode_field_expr(field_type: &Type) -> TokenStream2 {
    let field_size = field_repr_size(field_type);
    quote! {
        {
            let mut field_buf = <#field_type as ::spongefish::Decoding>::Repr::default();
            let end = offset + #field_size;
            ::spongefish::hybrid_array::AsArrayMut::as_array_mut(&mut field_buf)
                .copy_from_slice(&bytes[offset..end]);
            offset = end;
            <#field_type as ::spongefish::Decoding>::decode(field_buf)
        }
    }
}

fn generate_encoding_impl(input: &DeriveInput) -> Result<TokenStream2> {
    let fields = struct_fields(input, "Encoding")?;
    let bounded = bounded_types(&fields);

    let field_encodings = fields.iter().filter(|field| !field.skip).map(|field| {
        let member = &field.member;
        quote! {
            output.extend_from_slice(self.#member.encode().as_ref());
        }
    });

    let trait_path = quote!(::spongefish::Encoding);
    Ok(impl_block(
        input,
        &trait_path,
        &bounded,
        &quote! {
            fn encode(&self) -> impl AsRef<[u8]> {
                // Use the struct width as a hint for the encoded length.
                // For fields, this length is exact.
                let mut output = ::spongefish::__private::Vec::with_capacity(
                    ::core::mem::size_of::<Self>(),
                );
                #(#field_encodings)*
                output
            }
        },
    ))
}

fn generate_decoding_impl(input: &DeriveInput) -> Result<TokenStream2> {
    let fields = struct_fields(input, "Decoding")?;
    let bounded = bounded_types(&fields);

    let field_inits = fields.iter().map(|field| {
        let member = &field.member;
        if field.skip {
            return quote!(#member: Default::default(),);
        }
        let decode_field = decode_field_expr(field.ty);
        quote!(#member: #decode_field,)
    });

    let size_components = bounded.iter().copied().map(field_repr_size);
    let size_calc = if bounded.is_empty() {
        quote!(0usize)
    } else {
        quote!(#(#size_components)+*)
    };

    // Fields are decoded in declaration order.
    let decode_body = if bounded.is_empty() {
        quote! {
            let _ = buf;
            Self { #(#field_inits)* }
        }
    } else {
        quote! {
            let bytes = ::spongefish::hybrid_array::AsArrayRef::as_array_ref(&buf);
            let mut offset = 0usize;
            Self { #(#field_inits)* }
        }
    };

    let trait_path = quote!(::spongefish::Decoding);
    Ok(impl_block(
        input,
        &trait_path,
        &bounded,
        &quote! {
            type Repr = ::spongefish::hybrid_array::ArrayN<u8, { #size_calc }>;

            fn decode(buf: Self::Repr) -> Self {
                #decode_body
            }
        },
    ))
}

fn generate_narg_deserialize_impl(input: &DeriveInput) -> Result<TokenStream2> {
    let fields = struct_fields(input, "NargDeserialize")?;
    let bounded = bounded_types(&fields);

    let field_inits = fields.iter().map(|field| {
        let member = &field.member;
        if field.skip {
            return quote!(#member: Default::default(),);
        }
        let field_type = field.ty;
        quote! {
            #member: ::spongefish::NargReader::read::<#field_type>(reader)?,
        }
    });

    let trait_path = quote!(::spongefish::NargDeserialize);
    Ok(impl_block(
        input,
        &trait_path,
        &bounded,
        &quote! {
            fn deserialize_from_narg(
                reader: &mut ::spongefish::NargReader<'_>,
            ) -> ::core::result::Result<Self, ::spongefish::VerificationError> {
                // A unit struct, or one whose every field is skipped,
                // reads nothing at all.
                let _ = &reader;
                Ok(Self { #(#field_inits)* })
            }
        },
    ))
}

fn generate_unit_impl(input: &DeriveInput) -> Result<TokenStream2> {
    let fields = struct_fields(input, "Unit")?;
    let bounded = bounded_types(&fields);

    let zero_fields = fields.iter().map(|field| {
        let member = &field.member;
        if field.skip {
            return quote!(#member: ::core::default::Default::default(),);
        }
        let field_type = field.ty;
        quote!(#member: <#field_type as ::spongefish::Unit>::ZERO,)
    });

    let trait_path = quote!(::spongefish::Unit);
    Ok(impl_block(
        input,
        &trait_path,
        &bounded,
        &quote! {
            const ZERO: Self = Self { #(#zero_fields)* };
        },
    ))
}

/// Turns a generated impl into tokens, reporting failure as a `compile_error!`
/// on the offending span rather than as a proc-macro panic.
fn expand(generated: Result<TokenStream2>) -> TokenStream {
    TokenStream::from(generated.unwrap_or_else(syn::Error::into_compile_error))
}

/// Derive [`Encoding`](https://docs.rs/spongefish/latest/spongefish/trait.Encoding.html) for structs.
///
/// Fields marked with `#[spongefish(skip)]` are omitted from the encoding.
/// Any other `#[spongefish(..)]` form is a compile error.
///
/// # Security
///
/// Skip only values that are recomputable, or genuinely irrelevant to the statement being proven.
///
/// A skipped field is not bound by the Fiat-Shamir transformation, and therefore is never part of
/// the inputs to the random oracle, nor of the NARG string.
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
    expand(generate_encoding_impl(&input))
}

/// Derive macro for the [`Decoding`](https://docs.rs/spongefish/latest/spongefish/trait.Decoding.html) trait.
///
/// Generates an implementation that decodes struct fields sequentially from a fixed-size buffer.
/// Fields can be skipped using `#[spongefish(skip)]`.
///
/// The buffer is `hybrid_array::ArrayN<u8, N>` with `N` the sum of the fields'
/// widths, so `N` must be a size that crate supports: every width up to 512,
/// and the larger ones listed in its `sizes` module.
#[proc_macro_derive(Decoding, attributes(spongefish))]
pub fn derive_decoding(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand(generate_decoding_impl(&input))
}

/// Derive macro for the [`NargDeserialize`](https://docs.rs/spongefish/latest/spongefish/trait.NargDeserialize.html) trait.
///
/// Generates an implementation that deserializes struct fields sequentially from a byte buffer.
/// Fields can be skipped using `#[spongefish(skip)]`.
/// Parsing returns `VerificationError` on failure; use `NargReader::read` to
/// reject poisoned readers and automatically record nested field errors.
#[proc_macro_derive(NargDeserialize, attributes(spongefish))]
pub fn derive_narg_deserialize(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand(generate_narg_deserialize_impl(&input))
}

/// Derive macro that generates [`Encoding`](https://docs.rs/spongefish/latest/spongefish/trait.Encoding.html),
/// [`Decoding`](https://docs.rs/spongefish/latest/spongefish/trait.Decoding.html), and
/// [`NargDeserialize`](https://docs.rs/spongefish/latest/spongefish/trait.NargDeserialize.html) in one go.
#[proc_macro_derive(Codec, attributes(spongefish))]
pub fn derive_codec(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    expand((|| {
        let encoding = generate_encoding_impl(&input)?;
        let decoding = generate_decoding_impl(&input)?;
        let deserialize = generate_narg_deserialize_impl(&input)?;
        Ok(quote! {
            #encoding
            #decoding
            #deserialize
        })
    })())
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
    expand(generate_unit_impl(&input))
}

/// Whether a field carries `#[spongefish(skip)]`.
///
/// # Errors
///
/// Any `#[spongefish(..)]` that is not exactly `skip` is a compile error in the
/// deriving crate, reported on the attribute itself.
///
/// # Security
///
/// Dropping a field from the encoding map is security-relevant, so it must be
/// spelled out rather than inferred from an attribute that failed to parse:
/// `#[spongefish()]` parses zero nested metas, and a misspelling like
/// `#[spongefish(skpi)]` names no option at all. Neither may be read as "skip",
/// and neither may be silently ignored. See [`spongefish::Encoding`].
fn has_skip_attribute(attrs: &[syn::Attribute]) -> Result<bool> {
    for attr in attrs {
        if !attr.path().is_ident("spongefish") {
            continue;
        }

        let mut skip = false;
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("skip") {
                skip = true;
                Ok(())
            } else {
                Err(meta.error("unknown `spongefish` option; expected `skip`"))
            }
        })?;

        if !skip {
            return Err(syn::Error::new_spanned(
                attr,
                "empty `#[spongefish(..)]`: write `#[spongefish(skip)]` or remove the attribute",
            ));
        }
        return Ok(true);
    }

    Ok(false)
}
