use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

/// Procedural macro allowing a function to panic once and be retried if so
/// Panic is caught and then function's block is called again.
#[proc_macro_attribute]
pub fn retry_panic(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let ItemFn {
        attrs,
        vis,
        sig,
        block,
    } = parse_macro_input!(item as ItemFn);

    let wrapped_func = quote! {
        #(#attrs)*
        #vis #sig {
            // try to execute
            let state = std::panic::catch_unwind(|| {
                #block
            });

            // retry if panic
            match state {
                Ok(res) => res,
                Err(e) => {
                    println!("Test failed, retrying...");
                    #block
                }
            }
        }
    };

    TokenStream::from(wrapped_func)
}
