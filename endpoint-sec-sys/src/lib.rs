//! **Raw** manual bindings for the [Endpoint Security Framework][esf] for Apple targets (macOS)
//! (referred to as ES in the following documentation).
//!
//! Everything that was not present in the original release is feature gated to the macOS version
//! that saw it released, so you can ensure you don't use any newer functions and types. Additional
//! checks are done at runtime to return `None` or an `Err` when using something not yet available,
//! in the [`endpoint-sec`][esc] crate. This crate does not perform the checks since it contains the
//! raw types and `extern "C"` declaration. This is done because 1) the performance hit of a version
//! check is negligible in my experience and 2) even if compiled for a newer version where
//! information `A` is available, your program will still be able to handle older versions since `A`
//! will be returned in an `Option`.
//!
//! ## `Debug` implementations (and `PartialEq`, `Eq`, `Hash`)
//!
//! Several types do not have a [`Debug`] implementation because it depends on the [`es_message_t`]
//! `version` field. In this case, use the `endpoint-sec` crate, which bundle the version with
//! the data (for example with [`es_event_exec_t`]), allowing to implement `Debug`, [`PartialEq`],
//! [`Eq`] and [`Hash`] correctly.
//!
//! For lots of other types, it's because the implementation would be useless because they contain
//! pointers like [`es_string_token_t`]: implementing `Debug` for it in a useful way needs `unsafe`
//! code that we don't want to hide in a `Debug` impl. See the [`endpoint-sec`][esc] crate, with its
//! higher level types for useful `Debug` impls (and `PartialEq`, `Eq`, `Hash`).
//!
#![doc = concat!("[esc]: https://docs.rs/endpoint-sec/", env!("CARGO_PKG_VERSION"), "/endpoint-sec")]
//! [esf]: https://developer.apple.com/documentation/endpointsecurity

#![cfg(target_os = "macos")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![allow(
    deref_nullptr,
    non_camel_case_types,
    non_snake_case,
    clippy::bool_comparison,
    clippy::missing_safety_doc,
    clippy::undocumented_unsafe_blocks
)]
#![warn(
    unused_crate_dependencies,
    unreachable_pub,
    rustdoc::bare_urls,
    rustdoc::broken_intra_doc_links
)]

use core::{fmt, ptr};

/// A wrapper type around `*mut T` to communicate a pointer should not be null without introducing
/// undefined behaviour.
///
/// This is necessary for FFI, where, [`NonNull`][core::ptr::NonNull] asks for much stronger
/// guarantees, which we can't really provide when getting pointers from behind a C interface.
/// `ShouldNotBeNull` aims for the same usability as `NonNull` but with panics instead of undefined
/// behaviour when calling methods like [`as_ref()`][Self::as_ref].
///
/// Construction is done either directly from C since `ShouldNotBeNull` is a transparent wrapper or
/// with [`ShouldNotBeNull::new`].
#[repr(transparent)]
pub struct ShouldNotBeNull<T: ?Sized>(*mut T);

impl<T: ?Sized> Clone for ShouldNotBeNull<T> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: ?Sized> Copy for ShouldNotBeNull<T> {}

impl<T: ?Sized> ShouldNotBeNull<T> {
    /// Wraps `p` in a `ShouldNotBeNull`.
    #[inline]
    pub fn new(p: *mut T) -> Self {
        Self(p)
    }

    /// Calls [`as_ref()`][ptr_ref] on the inner pointer, panicking if it is null.
    ///
    /// # Safety
    ///
    /// See [`ptr::as_ref()`][ptr_ref] for the exact safety details.
    ///
    /// [ptr_ref]: https://doc.rust-lang.org/std/primitive.pointer.html#method.as_ref-1
    #[inline]
    pub unsafe fn as_ref<'a>(&self) -> &'a T {
        // Safety: see above
        unsafe { self.0.as_ref().expect("Pointer was null when it should not") }
    }

    /// Calls [`as_ref()`][ptr_ref] on the inner pointer.
    ///
    /// # Safety
    ///
    /// See [`ptr::as_ref()`][ptr_ref] for the exact safety details.
    ///
    /// [ptr_ref]: https://doc.rust-lang.org/std/primitive.pointer.html#method.as_ref-1
    #[inline]
    pub unsafe fn as_opt<'a>(&self) -> Option<&'a T> {
        // Safety: see above
        unsafe { self.0.as_ref() }
    }

    /// Access to the inner pointer as a `*const`
    #[inline]
    pub const fn as_ptr(self) -> *const T {
        self.0 as *const _
    }
}

impl<T: ?Sized> fmt::Debug for ShouldNotBeNull<T> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Pointer::fmt(&self.as_ptr(), f)
    }
}

impl<T: ?Sized> fmt::Pointer for ShouldNotBeNull<T> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Pointer::fmt(&self.as_ptr(), f)
    }
}

impl<T: ?Sized> Eq for ShouldNotBeNull<T> {}

impl<T: ?Sized> PartialEq for ShouldNotBeNull<T> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        ptr::eq(self.as_ptr(), other.as_ptr())
    }
}

/// Provides an unsafe wrapper to access some data as a slice in a type
macro_rules! slice_access {
    ($ty:ty[. $data:ident; . $count:ident]: fn $fn_name:ident() -> $slice_ty:ty) => {
        impl $ty {
            /// Uses `
            #[doc = ::core::stringify!($count)]
            /// ` and `
            #[doc = ::core::stringify!($data)]
            /// ` to give access to a slice view.
            ///
            /// # Safety
            ///
            /// The count and data should be in sync. If the count is not 0, the data should be a
            /// valid (aligned & non-null) pointer to initialized memory.
            #[inline]
            pub unsafe fn $fn_name(&self) -> &[$slice_ty] {
                if self.$count > 0 && self.$data.is_null() == false {
                    // Safety: `$data` is non-null, aligned (except if Apple mucked things up or the caller
                    // constructed an invalid value), `$data` is non-zero
                    unsafe { ::core::slice::from_raw_parts(self.$data, self.$count) }
                } else {
                    &[]
                }
            }
        }
    };
}

/// C enums cannot be directly represented as Rust enums, instead they have to be declared as
/// structs wrapping the correct integer (often an `u32`).
///
/// This macro will also ensure the `Debug` implemenation is nice to look at by showing the variant
/// instead of just the numeric value when it is known.
///
/// # Usage
///
/// In order for `== LAST` to work, variants must be defined in increasing numeric order. Failure to
/// do so will result in the `LAST` variant containing the wrong value.
macro_rules! ffi_wrap_enum {
    (
        $(#[$doc_enum:meta])*
        $enum_name: ident ($inner_type: ty);
        $(
            == LAST;
            $(#[$doc_last:meta])*
            $variant_last: ident,
        )?

        $(
            == MACOS_10_15_0;
            $(
                $(#[$doc_first:meta])*
                $variant_first: ident = $value_first: literal,
            )*

            --

            $(#[$doc_last_first:meta])*
            $variant_last_first: ident = $value_last_first: literal,
        )?
        $(
            == #[cfg(feature = $ver_feature_lit:literal)] $ver_ident:tt $ver_str:literal;
            $(
                $(#[$doc_ver:meta])*
                $variant_ver: ident = $value_ver: literal,
            )*

            --

            $(#[$doc_last_ver:meta])*
            $variant_last_ver: ident = $value_last_ver: literal,
        )*
    ) => {
        $(#[$doc_enum])*
        #[repr(transparent)]
        #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $enum_name(pub $inner_type);

        $(
            /// Variants available from macOS 10.15.0 onwards
            impl $enum_name {
                $(
                    $(#[$doc_first])*
                    pub const $variant_first: $enum_name = $enum_name($value_first);
                )*

                $(#[$doc_last_first])*
                ///
                /// Last value for macOS 10.15.0
                pub const $variant_last_first: $enum_name = $enum_name($value_last_first);

                /// Easily identifiable name for the last member of macOS 10.15.0
                pub const LAST_10_15_0: $enum_name = $enum_name::$variant_last_first;
            }
        )?
        $(
            paste::paste! {
                #[doc = "Variants available from macOS " $ver_str " onwards"]
                #[cfg(feature = $ver_feature_lit)]
                impl $enum_name {
                    $(
                        $(#[$doc_ver])*
                        pub const $variant_ver: $enum_name = $enum_name($value_ver);
                    )*

                    $(#[$doc_last_ver])*
                    ///
                    #[doc = "Last value for macOS " $ver_str]
                    pub const $variant_last_ver: $enum_name = $enum_name($value_last_ver);

                    #[doc = "Easily identifiable name for the last member of macOS " $ver_str]
                    pub const [<LAST_ $ver_ident>]: $enum_name = $enum_name::$variant_last_ver;
                }
            }
        )*

        impl $enum_name {
            const __COMPUTED_LAST_VARIANT: $enum_name = $enum_name({
                const LAST_VALUE: $enum_name = match &[
                    $($enum_name::$variant_last_first,)?
                    $(#[cfg(feature = $ver_feature_lit)] $enum_name::$variant_last_ver,)?
                ] {
                    [.., last] => *last,
                };

                LAST_VALUE.0 + 1
            });

            $(
                /// Not a real instance but a convenience value for operating on the range of defined
                /// variants.
                ///
                /// It can be used to ensure that, even on newer versions of Endpoint Security, you do not
                /// crash on unknown variants: if the variant value is superior or equal to this value (set
                /// at compile time), you can ignore it.
                ///
                /// See an example with [`es_event_type_t::ES_EVENT_TYPE_LAST`].
                pub const $variant_last: $enum_name = $enum_name::__COMPUTED_LAST_VARIANT;
            )?
        }

        impl ::core::fmt::Debug for $enum_name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                match *self {
                    $($(
                        Self::$variant_first => ffi_wrap_enum!(DEBUG f, $enum_name::$variant_first($value_first)),
                    )*)?
                    $(
                        Self::$variant_last_first => ffi_wrap_enum!(DEBUG f, $enum_name::$variant_last_first($value_last_first)),
                    )?
                    $(
                        $(
                            #[cfg(feature = $ver_feature_lit)]
                            Self::$variant_ver => ffi_wrap_enum!(DEBUG f, $enum_name::$variant_ver($value_ver)),
                        )*
                        #[cfg(feature = $ver_feature_lit)]
                        Self::$variant_last_ver => ffi_wrap_enum!(DEBUG f, $enum_name::$variant_last_ver($value_last_ver)),
                    )*
                    $(
                        Self::$variant_last => ::core::write!(
                            f, ::core::concat!(::core::stringify!($enum_name), "::", ::core::stringify!($variant_last), "({})"), self.0
                        ),
                    )?
                    unknown => ::core::write!(f, ::core::concat!(::core::stringify!($enum_name), "({})"), unknown.0),
                }
            }
        }
    };
    (DEBUG $f: ident, $enum_name: ident :: $variant_name: ident ($variant_value: literal)) => {
        ::core::write!($f, ::core::concat!(
            ::core::stringify!($enum_name), "::", ::core::stringify!($variant_name), "(", $variant_value, ")",
        ))
    }
}

/// Provides an access function for fields that are `ShouldNotBeNull<T>`
macro_rules! should_not_be_null_fields {
    ($ty: ty; $($field: ident -> $field_ty: ty),+ $(,)?) => {
        /// Accessors for `ShouldNotBeNull` fields
        impl $ty {
            $(
                /// Gives a references to the field while checking for null.
                ///
                /// # Safety
                ///
                /// See [`ShouldNotBeNull`][crate::ShouldNotBeNull] safety requirements.
                #[inline]
                pub unsafe fn $field(&self) -> &$field_ty {
                    // Safety: see above
                    unsafe { $crate::ShouldNotBeNull::as_ref(&self.$field) }
                }
            )+
        }
    };
}

/// Provides an access function for fields that are `*mut T` or `*const T`
macro_rules! null_fields {
    ($ty: ty; $($field: ident -> $field_ty: ty),+ $(,)?) => {
        /// Accessors for `*mut` and `*const` fields
        impl $ty {
            $(
                /// Helper to avoid the `is_null()` + deref every time.
                ///
                /// # Safety
                ///
                /// The pointer must be valid (aligned & initialized) for a value of the expected
                /// type.
                #[inline]
                pub unsafe fn $field(&self) -> Option<&$field_ty> {
                    // Safety: see above
                    unsafe { self.$field.as_ref() }
                }
            )+
        }
    };
}

mod types;
pub use types::*;

mod message;
pub use message::*;

mod client;
pub use client::*;

mod additional;
pub use additional::*;

// Helper due to Rust's orphan rule
mod result_wrapping;
pub use result_wrapping::*;
