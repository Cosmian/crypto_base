#![allow(
    non_upper_case_globals,
    non_snake_case,
    non_camel_case_types,
    dead_code,
    clippy::unreadable_literal,
    clippy::redundant_static_lifetimes,
    improper_ctypes,
    clippy::unseparated_literal_suffix,
    clippy::cognitive_complexity,
    clippy::upper_case_acronyms
)]

include!(concat!(env!("OUT_DIR"), "/sodium_bindings.rs"));
