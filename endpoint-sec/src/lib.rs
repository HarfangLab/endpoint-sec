//! Safe bindings for the [Endpoint Security Framework][esf] for Apple targets (macOS).
//!
//! The [`sys`] module contains the raw bindings since several types are publicly exported from there.
//!
//! At runtime, users should call [`version::set_runtime_version()`] before anything else, to indicate
//! on which macOS version the app is running on.
//!
//! The entry point is the [`Client`] type, which is a wrapper around [`es_client_t`][sys::es_client_t],
//! with the [`Client::new()`] method.
//!
//! After a `Client` has been created, [events][sys::es_event_type_t] can be subscribed to
//! using [`Client::subscribe()`]. Each time Endpoint Security gets an event that is part of the
//! subscribptions for your client, it will call the handler that was given to `Client::new()` with
//! the [message][Message] associated to the event. Note that `AUTH` events have an associated
//! deadline before which your handler must give a response else your client may be killed by macOS
//! to avoid stalling for the user.
//!
//! [esf]: https://developer.apple.com/documentation/endpointsecurity

#![cfg(target_os = "macos")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![allow(clippy::bool_comparison)]
#![warn(
    missing_docs,
    unused_crate_dependencies,
    clippy::missing_safety_doc,
    unreachable_pub,
    clippy::missing_docs_in_private_items
)]

// Reexports [`endpoint_sec_sys`]
pub use endpoint_sec_sys as sys;
#[cfg(all(test, not(feature = "audit_token_from_pid")))]
use sysinfo as _;

/// Our wrappers around Endpoint Security events cannot easily implement [`Debug`]: they contain
/// a reference to the original value (and sometimes the version). Since the structs behind the
/// references can change shape based on macOS' versions, we cannot rely on the one compiled in
/// our Rust bindings. What's more, some fields are only available in some versions of Endpoint
/// Security, others are behind pointers and associated with another (eg, array + len). This macro
/// makes it easier to implement [`Debug`] by simply passing the type and the functions to use for
/// the `Debug` impl. See examples of usage in the modules below.
macro_rules! impl_debug_eq_hash_with_functions {
    ($ty:ident$(<$lt: lifetime>)? $(with $version:ident)?; $($(#[$fmeta: meta])? $fname:ident),* $(,)?) =>  {
        impl $(<$lt>)? ::core::fmt::Debug for $ty $(<$lt>)? {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                let mut d = f.debug_struct(::core::stringify!($ty));
                $( d.field("version", &self.$version); )?
                $( $(#[$fmeta])? d.field(::core::stringify!($fname), &self.$fname()); )*
                d.finish()
            }
        }

        impl $(<$lt>)? ::core::cmp::PartialEq for $ty $(<$lt>)? {
            #[allow(unused_variables)]
            fn eq(&self, other: &Self) -> bool {
                $( if ::core::cmp::PartialEq::ne(&self.$version, &other.$version) { return false } )?
                $( $(#[$fmeta])? if ::core::cmp::PartialEq::ne(&self.$fname(), &other.$fname()) { return false; } )*
                true
            }
        }

        impl $(<$lt>)? ::core::cmp::Eq for $ty $(<$lt>)? {}

        impl $(<$lt>)? ::core::hash::Hash for $ty $(<$lt>)? {
            #[allow(unused_variables)]
            fn hash<H: ::core::hash::Hasher>(&self, state: &mut H) {
                $( ::core::hash::Hash::hash(&self.$version, state); )?
                $( $(#[$fmeta])? ::core::hash::Hash::hash(&self.$fname(), state); )*
            }
        }

    };
}

/// Helper macro to generate all necessary version checks for a function call.
macro_rules! versioned_call {
    // It's not possible to use `feature = ::std::concat(...)` so we need to pass both forms.
    (if cfg!($cfg: meta) && version >= ($major:literal, $minor:literal, $patch:literal) { $($if_tt:tt)* } $(else { $($else_tt:tt)* })?) => {
        if ::std::cfg!($cfg) && $crate::version::is_version_or_more($major, $minor, $patch) {
            #[cfg($cfg)]
            { $($if_tt)* }
            #[cfg(not($cfg))]
            // Safety: the cfg was checked just above
            unsafe { ::std::hint::unreachable_unchecked() }
        } $( else {
            $($else_tt)*
        } )?
    };
}

// Publicly reexported modules
#[cfg(feature = "macos_10_15_1")]
mod acl;
mod action;
mod audit;
mod client;
mod event;
mod message;
mod mute;
// Not public
mod utils;

#[cfg(feature = "macos_10_15_1")]
pub use acl::*;
pub use action::*;
pub use audit::*;
pub use client::*;
pub use event::*;
pub use message::*;
pub use mute::*;

/// Helper module to avoid implementing version detection in this crate and make testing easier
/// by telling the crate its on a lower version than the real one.
pub mod version {
    use std::sync::atomic::{AtomicU64, Ordering};

    /// macOS major version
    static MAJOR: AtomicU64 = AtomicU64::new(10);
    /// macOS minor version
    static MINOR: AtomicU64 = AtomicU64::new(15);
    /// macOS patch version
    static PATCH: AtomicU64 = AtomicU64::new(0);

    /// Setup the runtime version of macOS, detected outside of this library.
    ///
    /// Conservatively, this library assumes the default is 10.15.0 and will refuse to use functions
    /// that only became available in later version of macOS and Endpoint Security.
    ///
    /// Methods on [`Client`][super::Client] will check this version when calling a function only
    /// available in macOS 11+ for example.
    ///
    /// # Panics
    ///
    /// Will panic if attempting to set a version below 10.15.0.
    pub fn set_runtime_version(major: u64, minor: u64, patch: u64) {
        if major < 10 || (major == 10 && minor < 15) {
            panic!("Endpoint Security cannot run on versions inferiors to 10.15.0");
        }

        MAJOR.store(major, Ordering::Release);
        MINOR.store(minor, Ordering::Release);
        PATCH.store(patch, Ordering::Release);
    }

    /// `true` if the version setup in [`set_runtime_version()`] is at least the given
    /// `major.minor.patch` here.
    pub fn is_version_or_more(major: u64, minor: u64, patch: u64) -> bool {
        let current_major = MAJOR.load(Ordering::Acquire);
        let current_minor = MINOR.load(Ordering::Acquire);
        let current_patch = PATCH.load(Ordering::Acquire);

        (current_major, current_minor, current_patch) >= (major, minor, patch)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        #[should_panic(expected = "Endpoint Security cannot run on versions inferiors to 10.15.0")]
        fn test_cannot_set_version_major_under_10() {
            set_runtime_version(9, 16, 2);
        }

        #[test]
        #[should_panic(expected = "Endpoint Security cannot run on versions inferiors to 10.15.0")]
        fn test_cannot_set_version_minor_under_10_15() {
            set_runtime_version(10, 14, 0);
        }

        #[test]
        fn test_is_version_or_more_with_set_runtime() {
            set_runtime_version(10, 15, 0);

            assert!(is_version_or_more(10, 14, 99));
            assert!(is_version_or_more(9, 15, 0));
            assert!(is_version_or_more(9, 14, 1));
            assert!(is_version_or_more(10, 15, 0));

            assert!(!is_version_or_more(12, 3, 1));
            assert!(!is_version_or_more(13, 3, 2));
            assert!(!is_version_or_more(14, 5, 4));
            assert!(!is_version_or_more(15, 0, 0));

            set_runtime_version(13, 3, 2);

            assert!(is_version_or_more(12, 3, 1));
            assert!(is_version_or_more(13, 3, 2));
            assert!(!is_version_or_more(14, 5, 4));
            assert!(!is_version_or_more(15, 0, 0));
        }
    }
}
