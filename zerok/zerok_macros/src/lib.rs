use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{parse_macro_input, AttributeArgs, Ident, Item, Lit, Meta, MetaList, NestedMeta};

/// Generate round-trip serialization tests.
///
/// The attribute `ser_test` can be applied to a struct or enum definition to automatically derive
/// round-trip serialization tests for serde and ark_serialize impls. The generated tests follow the
/// pattern:
/// * Create an instance of the type under test, using a mechanism seleected by the arguments to the
///   attribute macro (see Arguments below)
/// * Serialize the instance, checking that it succeeds
/// * Deserialize the serialized data and compare the result to the original instance
///
/// There are a few requirements on the type being tested:
/// * It must not be generic
/// * It must implement `Debug` and `PartialEq`
/// * It must implement `Default` unless a different construction method is used (see below)
/// * It must implement `Serialize` and `DeserializeOwned` unless `serde(false)` is used
/// * It must implement `CanonicalSerialize` and `CanonicalDeserialize` unless `ark(false)` is used
///
/// # Example
/// ```
/// use arbitrary::Arbitrary;
/// use ark_serialize::*;
/// use rand_chacha::ChaChaRng;
/// use serde::{Serialize, Deserialize};
/// use zerok_macros::ser_test;
///
/// // Deriving serde and ark_serialize tests using a default instance.
/// #[ser_test]
/// #[derive(
///     Debug, Default, PartialEq, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize
/// )]
/// struct S1;
///
/// // Deriving serde tests only.
/// #[ser_test(ark(false))]
/// #[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
/// struct S2;
///
/// // Deriving ark_serialize tests using an arbitrary instance.
/// #[ser_test(arbitrary, serde(false))]
/// #[derive(Arbitrary, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
/// struct S3;
///
/// // Deriving tests using a random instance.
/// #[ser_test(random, ark(false))]
/// #[derive(Debug, PartialEq, Serialize, Deserialize)]
/// struct S4;
///
/// impl S4 {
///     fn random(rng: &mut ChaChaRng) -> Self {
///         S4
///     }
/// }
///
/// // Deriving tests using a random constructor with a non-standard name.
/// #[ser_test(random(random_for_test), ark(false))]
/// #[derive(Debug, PartialEq, Serialize, Deserialize)]
/// struct S5;
///
/// impl S5 {
///     #[cfg(test)]
///     fn random_for_test(rng: &mut ChaChaRng) -> Self {
///         S5
///     }
/// }
///
/// // Deriving tests using a custom constructor to get an instance.
/// #[ser_test(constr(new), ark(false))]
/// #[derive(Debug, PartialEq, Serialize, Deserialize)]
/// struct S6;
///
/// impl S6 {
///     fn new() -> Self {
///         S6
///     }
/// }
/// ```
///
/// # Arguments
/// * `ark([true|false])` opt in or out of `ark_serialize` tests (the default is `true`)
/// * `serde([true|false])` opt in or out of `serde` tests (the default is `true`)
/// * `arbitrary` use the type's `Arbitrary` implementation instead of `Default` to construct a test
///   instance
/// * `random` use the type's `random` associated function instead of `Default` to construct the
///   test instance. The `random` constructor must have a signature compatible with
///   `fn random(&mut ChaChaRng) -> Self`
/// * `random(f)` use the type's associated function `f` instead of `Default` to construct the test
///   instance. `f` mut have a signature compatible with `fn f(&mut ChaChaRng) -> Self`
/// * `constr(f)` use the type's associated function `f` instead of `Default` to construct the test
///   instance. `f` must have the signature `fn f() -> Self`
#[proc_macro_attribute]
pub fn ser_test(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as AttributeArgs);
    let input = parse_macro_input!(input as Item);
    let name = match &input {
        Item::Struct(item) => &item.ident,
        Item::Enum(item) => &item.ident,
        _ => panic!("expected struct or enum"),
    };

    // Parse arguments.
    let mut constr = quote! { #name::default() };
    let mut test_ark = true;
    let mut test_serde = true;
    for arg in args {
        match arg {
            // Path arguments (as in #[ser_test(arg)])
            NestedMeta::Meta(Meta::Path(path)) => match path.get_ident() {
                Some(id) if *id == "random" => {
                    constr = random_constr(name, id);
                }

                Some(id) if *id == "arbitrary" => {
                    constr = arbitrary_constr(name);
                }

                _ => panic!("invalid argument {:?}", path),
            },

            // List arguments (as in #[ser_test(arg(val))])
            NestedMeta::Meta(Meta::List(MetaList { path, nested, .. })) => match path.get_ident() {
                Some(id) if *id == "random" => {
                    if nested.len() != 1 {
                        panic!("random attribute takes 1 argument");
                    }
                    match &nested[0] {
                        NestedMeta::Meta(Meta::Path(p)) => match p.get_ident() {
                            Some(id) => {
                                constr = random_constr(name, id);
                            }
                            None => panic!("random argument must be an identifier"),
                        },
                        _ => panic!("random argument must be an identifier"),
                    }
                }

                Some(id) if *id == "constr" => {
                    if nested.len() != 1 {
                        panic!("constr attribute takes 1 argument");
                    }
                    match &nested[0] {
                        NestedMeta::Meta(Meta::Path(p)) => match p.get_ident() {
                            Some(id) => {
                                constr = assoc_constr(name, id);
                            }
                            None => panic!("constr argument must be an identifier"),
                        },
                        _ => panic!("constr argument must be an identifier"),
                    }
                }

                Some(id) if *id == "ark" => {
                    if nested.len() != 1 {
                        panic!("ark attribute takes 1 argument");
                    }
                    match &nested[0] {
                        NestedMeta::Lit(Lit::Bool(b)) => {
                            test_ark = b.value;
                        }
                        _ => panic!("ark argument must be a boolean"),
                    }
                }

                Some(id) if *id == "serde" => {
                    if nested.len() != 1 {
                        panic!("serde attribute takes 1 argument");
                    }
                    match &nested[0] {
                        NestedMeta::Lit(Lit::Bool(b)) => {
                            test_serde = b.value;
                        }
                        _ => panic!("serde argument must be a boolean"),
                    }
                }

                _ => panic!("invalid attribute {:?}", path),
            },

            _ => panic!("invalid argument {:?}", arg),
        }
    }

    let serde_test = if test_serde {
        let test_name = Ident::new(
            &format!("ser_test_serde_round_trip_{}", name),
            Span::mixed_site(),
        );
        quote! {
            #[cfg(test)]
            #[test]
            fn #test_name() {
                let obj = #constr;
                let buf = bincode::serialize(&obj).unwrap();
                assert_eq!(obj, bincode::deserialize(&buf).unwrap());
            }
        }
    } else {
        quote! {}
    };

    let ark_test = if test_ark {
        let test_name = Ident::new(
            &format!("ser_test_ark_serialize_round_trip_{}", name),
            Span::mixed_site(),
        );
        quote! {
            #[cfg(test)]
            #[test]
            fn #test_name() {
                use ark_serialize::*;
                let obj = #constr;
                let mut buf = Vec::new();
                CanonicalSerialize::serialize(&obj, &mut buf).unwrap();
                assert_eq!(obj, CanonicalDeserialize::deserialize(buf.as_slice()).unwrap());
            }
        }
    } else {
        quote! {}
    };

    let output = quote! {
        #input
        #serde_test
        #ark_test
    };
    output.into()
}

// Test instance construction methods.
fn assoc_constr(name: &Ident, f: &Ident) -> proc_macro2::TokenStream {
    quote! { #name::#f() }
}

fn random_constr(name: &Ident, f: &Ident) -> proc_macro2::TokenStream {
    quote! {
        {
            use rand_chacha::{rand_core::SeedableRng, ChaChaRng};
            let mut rng = ChaChaRng::from_seed([42u8; 32]);
            #name::#f(&mut rng)
        }
    }
}

fn arbitrary_constr(name: &Ident) -> proc_macro2::TokenStream {
    quote! {
        {
            use arbitrary::Unstructured;
            use rand_chacha::{rand_core::{RngCore, SeedableRng}, ChaChaRng};
            let mut rng = ChaChaRng::from_seed([42u8; 32]);
            let mut data = vec![0u8; 1024];
            rng.fill_bytes(&mut data);
            Unstructured::new(&data).arbitrary::<#name>().unwrap()
        }
    }
}
