use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{parse2, parse_macro_input, Attribute, Item, ItemFn, ItemMod};

/// Define a set of generic tests which can be instantiated with different type parameters.
///
/// When applied to a module, `generic_tests` will transform the contents of that module as follows.
/// For each test function in the module (a test function is any function with an attribute ending
/// in `test` or `bench`, e.g. `#[test]` or `#[async_std::test]`), the test-relevant attributes
/// `#[test]`, `#[ignore]`, etc. will be removed. Otherwise, all items are left in the module
/// unchanged.
///
/// A macro will be added to the module which can be used to instantiate the generic tests in the
/// module. The name of the macro is `instantiate_` followed by the module name. Invoking the macro
/// with a list of type parameters in any context where the generic tests module is in scope is
/// equivalent to defining, for each test function in the module, a test function of the same name,
/// with the test-relevant attributes of the original generic function, whose body simply invokes
/// the generic function from the module with the given type parameters.
///
/// Note that, unlike normal test modules, all test functions must be public, since they will be
/// invoked from wherever the instantiate macro is invoked, which will be outside the module where
/// the tests are defined.
///
/// Also note that the instantiate macro is subject to the usual constraints on macro visibility. It
/// can only be used in a context that is lexically after the module where it is defined. To use it
/// from a module other than the one containing the generic tests module, all parent modules between
/// the generic tests module and the common ancestor of the invoking module must be annotated with
/// #[macro_use]. To use it from a different crate, `use my_crate::instantiate_macro` is required,
/// where `my_crate` is the external name of the crate containing the generic tests module.
///
/// # Example
/// ```
/// use zerok_macros::generic_tests;
///
/// #[generic_tests]
/// mod tests {
///     #[test]
///     pub fn a_test<T: std::fmt::Debug + Default + PartialEq>() {
///         assert_eq!(T::default(), T::default());
///     }
/// }
///
/// #[cfg(test)]
/// mod specific_tests {
///     use super::tests;
///     instantiate_tests!(u32);
///     instantiate_tests!(Vec<u32>);
/// }
/// ```
///
/// # TODO
/// A better way of declaring the instantiate macro would be to name it, simply, `instantiate`, and
/// always reference it by qualified name, e.g. `tests::instantiate!(u32)`. This would eliminate the
/// requirement of bringing both the tests module and the macro into scope separately before
/// invoking the macro. I believe this is possible with the 2021 edition of Rust, but in the 2018
/// edition macros don't behave like normal items of modules, and cannot be referenced by qualified
/// path.
///
pub fn generic_tests(_args: TokenStream, input: TokenStream) -> TokenStream {
    let mut test_mod: ItemMod = parse_macro_input!(input);
    let name = &test_mod.ident;

    test_mod.content = test_mod.content.map(|(brace, items)| {
        let macro_name = format_ident!("instantiate_{}", name);
        let mut macro_body = proc_macro2::TokenStream::new();

        // Transform each item in the module by removing test attributes. For each test function
        // (function item which has at least one test attribute) append a monomorphized test
        // function to `macro_body`.
        let mut items = items
            .into_iter()
            .map(|item| {
                if let Item::Fn(mut f) = item {
                    let test_attrs = take_test_attrs(&mut f);
                    if !test_attrs.is_empty() {
                        let mut test_sig = f.sig.clone();
                        // The actual test function which gets defined by the macro must not have
                        // any generics.
                        test_sig.generics = Default::default();
                        let test_name = &test_sig.ident;
                        // The macro will take `$t:ty` as a parameter, so we can use `$t` to invoke
                        // the generic function with specific type parameters.
                        let basic_call = quote!(#name::#test_name::<$($t),*>());
                        // Async test functions require an `await`.
                        let call = if test_sig.asyncness.is_some() {
                            quote!(#basic_call.await)
                        } else {
                            basic_call
                        };
                        macro_body.extend(quote! {
                            #(#test_attrs)*
                            #test_sig {
                                #call
                            }
                        });
                    }
                    Item::Fn(f)
                } else {
                    item
                }
            })
            .collect::<Vec<_>>();

        items.push(
            parse2(quote! {
                #[macro_export]
                macro_rules! #macro_name {
                    ($($t:ty),*) => {
                        #macro_body
                    };
                }
            })
            .unwrap(),
        );

        (brace, items)
    });

    let output = quote! {
        #[macro_use]
        #test_mod
    };
    output.into()
}

fn take_test_attrs(f: &mut ItemFn) -> Vec<Attribute> {
    let (test_attrs, other_attrs) = std::mem::take(&mut f.attrs)
        .into_iter()
        .partition(is_test_attr);
    f.attrs = other_attrs;
    test_attrs
}

fn is_test_attr(attr: &Attribute) -> bool {
    matches!(
        attr.path
            .segments
            .last()
            .unwrap()
            .ident
            .to_string()
            .as_str(),
        "test" | "ignore" | "bench" | "should_panic"
    )
}
