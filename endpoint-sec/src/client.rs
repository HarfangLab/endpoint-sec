//! Expose a wrapper around [`es_client_t`]: [`Client`]
use std::ffi::OsStr;
#[cfg(doc)]
use std::ffi::OsString;
use std::marker::PhantomData;
use std::os::unix::prelude::OsStrExt;
use std::panic::{catch_unwind, RefUnwindSafe};
use std::ptr::NonNull;

use endpoint_sec_sys::*;

use crate::utils::convert_byte_slice_to_cow_cstr;
use crate::{AuditToken, Message};
#[cfg(feature = "macos_12_0_0")]
use crate::{MutedPath, MutedProcess};

/// Wrapper around the opaque type that stores the ES client state.
///
/// Note: this implementation ignores the return value of [`es_delete_client`] if you use [`Drop`],
/// use [`Client::delete()`] instead if you want to check it.
///
/// This type is neither [`Send`] nor [`Sync`] because the client must be released on the same
/// thread it was created.
#[doc(alias = "es_client_t")]
pub struct Client<'b> {
    /// Pointer to the client, internal state is managed by Apple, we just keep it to pass it in
    /// functions.
    ///
    /// Once constructed, it must never be `null`.
    inner: NonNull<es_client_t>,

    /// Ensure the client cannot outlive its message handling closure.
    block_lifetime: PhantomData<&'b ()>,
}

static_assertions::assert_not_impl_any!(Client: Send, Sync);

/// Helper macro for functions that give us memory we need to free
macro_rules! to_vec_and_free {
    ($this:expr, $wrapped_function:ident) => {{
        let mut count = 0;
        let mut data = ::std::ptr::null_mut();

        // Safety:
        // - `self.as_mut()` is a valid client by construction
        // - `count` is mutable
        // - `data` is a mutable pointer
        // - result is checked
        // - `data` is freed below, since Apple says in its docs we have ownership of the memory
        unsafe { $wrapped_function($this.as_mut(), &mut count, &mut data) }.ok()?;

        let vec_data = if count > 0 && !data.is_null() {
            // Safety:
            // - `count > 0` so we won't create a zero-length slice
            // - `data` is aligned and not null
            unsafe { ::std::slice::from_raw_parts(data, count) }.to_vec()
        } else {
            ::std::vec::Vec::new()
        };

        if !data.is_null() {
            // Safety: We have copied the data into a heap-allocated Vec,
            // we can free it without losing data now and we have checked it
            // is not null
            unsafe { ::libc::free(data.cast()) };
        }

        Ok(vec_data)
    }};
    // Only calls the `$wrapped_function`, useful when the data structure has a custom function
    // for deallocation
    ($this:expr, $wrapped_function:ident with custom free) => {{
        let mut data = ::std::ptr::null_mut();

        // Safety:
        // - `self.as_mut()` is a valid client by construction
        // - `data` is a mutable pointer
        // - result is checked
        // - `data` is freed below the macro call, with the custom function provided by Apple
        unsafe { $wrapped_function($this.as_mut(), &mut data) }.ok()?;

        data
    }};
}

/// Public bindings to the underlying [`es_client_t`] API.
impl Client<'_> {
    /// Creates a new [`Client`].
    ///
    /// Callers must respect the following requirement if they want this function to succeed:
    ///
    /// - Have the necessary entitlement for Endpoint Security
    /// - Have the user's approval (TCC)
    /// - Be running as root when launching the client (and while it is active)
    /// - Not have previously reached the maximum number of connected clients
    ///
    /// See [`es_new_client()`].
    #[doc(alias = "es_new_client")]
    pub fn new<'b, F>(handler: F) -> Result<Client<'b>, NewClientError>
    where
        F: Fn(&mut Client<'_>, Message) + RefUnwindSafe + 'b,
    {
        let mut client = std::ptr::null_mut();

        let block_handler = block2::ConcreteBlock::new(
            move |client: NonNull<es_client_t>, message: NonNull<es_message_t>| {
                let _err = catch_unwind(|| {
                    // Safety: Apple guarantees the received message is non-null and valid
                    let message = unsafe { Message::from_raw(message) };
                    let mut client = Client {
                        inner: client,
                        block_lifetime: PhantomData,
                    };

                    handler(&mut client, message);
                    // Forget the client, else it would be double-dropped
                    std::mem::forget(client);
                });
            },
        );

        // Safety:
        // - `handler` is 'b so we can keep a ref through it in `block_handler` without trouble
        // - The result is checked with `.ok()` below
        unsafe { es_new_client(&mut client, &block_handler) }.ok()?;

        // Safety: Apple guarantees the received client is non-null and valid since we have checked
        // the result of `es_new_client`.
        Ok(Client {
            inner: unsafe { NonNull::new_unchecked(client) },
            block_lifetime: PhantomData,
        })
    }

    /// Subscribe the client to `events`, without removing previous subscriptions.
    ///
    /// # Panics
    ///
    /// `events` can contain at most `u32::MAX` elements. This is a limitation of Apple's API.
    ///
    /// See [`es_subscribe`].
    #[doc(alias = "es_subscribe")]
    #[inline(always)]
    pub fn subscribe(&mut self, events: &[es_event_type_t]) -> Result<(), ReturnError> {
        assert!(events.len() < u32::MAX as usize);

        // Safety:
        // - `self.as_mut()` is a valid client by construction
        // - `events` is a slice for which we have checked the length, `.as_ptr()` and `.len() as
        //   u32` are both valid
        // - the result is checked with `.ok()`
        unsafe { es_subscribe(self.as_mut(), events.as_ptr(), events.len() as u32) }.ok()
    }

    /// Unsubscribe the client from `events`, without removing other subscriptions.
    ///
    /// # Panics
    ///
    /// `events` can contain at most `u32::MAX` elements. This is a limitation of Apple's API.
    ///
    /// See [`es_unsubscribe`].
    #[doc(alias = "es_unsubscribe")]
    #[inline(always)]
    pub fn unsubscribe(&mut self, events: &[es_event_type_t]) -> Result<(), ReturnError> {
        assert!(events.len() < u32::MAX as usize);

        // Safety:
        // - `self.as_mut()` is a valid client by construction
        // - `events` is a slice for which we have checked the length, `.as_ptr()` and `.len() as
        //   u32` are both valid
        // - the result is checked with `.ok()`
        unsafe { es_unsubscribe(self.as_mut(), events.as_ptr(), events.len() as u32) }.ok()
    }

    /// Unsubscribe the client from all its current subscriptions.
    ///
    /// See [`es_unsubscribe_all`].
    #[doc(alias = "es_unsubscribe_all")]
    #[inline(always)]
    pub fn unsubscribe_all(&mut self) -> Result<(), ReturnError> {
        // Safety:
        // - `self.as_mut()` is a valid client by construction
        // - the result is checked with `.ok()`
        unsafe { es_unsubscribe_all(self.as_mut()) }.ok()
    }

    /// List current subscriptions of client.
    ///
    /// See [`es_subscriptions`].
    #[doc(alias = "es_subscriptions")]
    pub fn subscriptions(&mut self) -> Result<Vec<es_event_type_t>, ReturnError> {
        to_vec_and_free!(self, es_subscriptions)
    }

    /// Respond to an auth event.
    ///
    /// See [`es_respond_auth_result`]
    #[doc(alias = "es_respond_auth_result")]
    #[inline(always)]
    pub fn respond_auth_result(
        &mut self,
        msg: &Message,
        resp: es_auth_result_t,
        cache: bool,
    ) -> Result<(), RespondError> {
        // Safety:
        // - `self.as_mut()` is a valid client by construction
        // - `msg` is a ref to a valid message
        // - the result is checked with `.ok()`
        unsafe { es_respond_auth_result(self.as_mut(), msg.get_raw_ref(), resp, cache) }.ok()
    }

    /// Respong to an auth event that needs a flag response.
    ///
    /// See [`es_respond_flags_result`]
    #[doc(alias = "es_respond_flags_result")]
    #[inline(always)]
    pub fn respond_flags_result(
        &mut self,
        msg: &Message,
        authorized_flags: u32,
        cache: bool,
    ) -> Result<(), RespondError> {
        // Safety:
        // - `self.as_mut()` is a valid client by construction
        // - `msg` is a ref to a valid message
        // - the result is checked with `.ok()`
        unsafe { es_respond_flags_result(self.as_mut(), msg.get_raw_ref(), authorized_flags, cache) }.ok()
    }

    /// Fully mute the given process.
    ///
    /// See [`es_mute_process`].
    #[doc(alias = "es_mute_process")]
    #[inline(always)]
    pub fn mute_process(&mut self, process: &AuditToken) -> Result<(), ReturnError> {
        // Safety:
        // - `self.as_mut()` is a valid client by construction
        // - `process` is valid (not-null, aligned) since its a reference cast to a pointer
        unsafe { es_mute_process(self.as_mut(), process.get_raw_ref()) }.ok()
    }

    /// Mute only some events for the given process.
    ///
    /// See [`es_mute_process_events`].
    ///
    /// Only available on macOS 12.0+.
    #[doc(alias = "es_mute_process_events")]
    #[cfg(feature = "macos_12_0_0")]
    pub fn mute_process_events(&mut self, process: &AuditToken, events: &[es_event_type_t]) -> Result<(), ReturnError> {
        if crate::version::is_version_or_more(12, 0, 0) == false {
            return Err(ReturnError::ApiUnavailable);
        }

        // Safety:
        // - `self.as_mut()` is a valid client by construction
        // - `process` is valid (non-null, aligned) since its a reference cast to a pointer
        // - size and data of `events` are correctly passed in conjunction
        unsafe {
            es_mute_process_events(
                self.as_mut(),
                process.get_raw_ref(),
                events.as_ptr(),
                events.len(),
            )
        }
        .ok()
    }

    /// Fully unmute the given process.
    ///
    /// See [`es_unmute_process`].
    #[doc(alias = "es_unmute_process")]
    #[inline(always)]
    pub fn unmute_process(&mut self, process: &AuditToken) -> Result<(), ReturnError> {
        // Safety:
        // - `self.as_mut()` is a valid client by construction
        // - `process` is valid (not-null, aligned) since its a reference cast to a pointer
        unsafe { es_unmute_process(self.as_mut(), process.get_raw_ref()) }.ok()
    }

    /// Unmute only some events for the given process.
    ///
    /// See [`es_unmute_process_events`].
    ///
    /// Only available on macOS 12.0+.
    #[doc(alias = "es_unmute_process_events")]
    #[cfg(feature = "macos_12_0_0")]
    pub fn unmute_process_events(
        &mut self,
        process: &AuditToken,
        events: &[es_event_type_t],
    ) -> Result<(), ReturnError> {
        if crate::version::is_version_or_more(12, 0, 0) == false {
            return Err(ReturnError::ApiUnavailable);
        }

        // Safety:
        // - `self.as_mut()` is a valid client by construction
        // - `process` is valid (non-null, aligned) since its a reference cast to a pointer
        // - size and data of `events` are correctly passed in conjunction
        unsafe {
            es_unmute_process_events(
                self.as_mut(),
                process.get_raw_ref(),
                events.as_ptr(),
                events.len(),
            )
        }
        .ok()
    }

    /// List muted processes.
    ///
    /// The returned [`AuditToken`] are in the same state as they were passed in to
    /// [`Self::mute_process()`] and may not accuretly reflect the current state of the respective processes.
    ///
    /// See [`es_muted_processes`].
    ///
    /// Deprecated in macOS 12.0+
    #[doc(alias = "es_muted_processes")]
    pub fn muted_processes(&mut self) -> Result<Vec<AuditToken>, ReturnError> {
        let raw_result = to_vec_and_free!(self, es_muted_processes);

        match raw_result {
            Ok(raw_result) => Ok(raw_result.into_iter().map(AuditToken::new).collect()),
            Err(error) => Err(error),
        }
    }

    /// List muted processes with additional informations
    ///
    /// See [`es_muted_processes_events`].
    ///
    /// Only available on macOS 12.0+.
    #[doc(alias = "es_muted_processes_events")]
    #[doc(alias = "es_release_muted_processes")]
    #[cfg(feature = "macos_12_0_0")]
    pub fn muted_processes_events(&mut self) -> Result<Vec<MutedProcess>, ReturnError> {
        if crate::version::is_version_or_more(12, 0, 0) == false {
            return Err(ReturnError::ApiUnavailable);
        }
        let data = to_vec_and_free!(
            self,
            es_muted_processes_events
            with custom free
        );

        let muted_processes = if data.is_null() {
            Vec::new()
        } else {
            // Safety: `data` is non-null we checked, let's hope Apple didn't ignore alignment
            let sl = unsafe { (*data).processes() };

            let mut muted_processes = Vec::with_capacity(sl.len());
            for muted_process in sl {
                muted_processes.push(MutedProcess {
                    audit_token: AuditToken::new(muted_process.audit_token),
                    // Safety: if we were not lied to by ES, this is okay: the pointer is null if
                    // the size is zero, and valid if the size is not zero
                    events: unsafe { muted_process.events() }.into(),
                });
            }

            // Safety:
            // - `data` is non null and hopefully valid for this
            // - there is no return to check
            unsafe { es_release_muted_processes(data) };

            muted_processes
        };

        Ok(muted_processes)
    }

    /// Mute a path for all event types.
    ///
    #[cfg_attr(feature = "macos_12_0_0", doc = "See [`es_mute_path`].")]
    #[cfg_attr(not(feature = "macos_12_0_0"), doc = "See `es_mute_path`.")]
    ///
    /// # Note
    ///
    /// The C function takes a `const char * _Nonnull path`, which means it expects a nul-
    /// terminated string. Since the functions to gather such paths give [`OsString`]s (ex:
    #[cfg_attr(
        feature = "macos_12_0_0",
        doc = "[`Self::muted_paths_events`]), this method will truncate the given `path` to the first `\0`"
    )]
    #[cfg_attr(
        not(feature = "macos_12_0_0"),
        doc = "`Self::muted_paths_events`), this method will truncate the given `path` to the first `\0`"
    )]
    /// if it has one or add it itself if it does not (in which case there will be an allocation).
    ///
    #[cfg_attr(
        feature = "macos_12_0_0",
        doc = "- If called on macOS 12.0+: uses [`es_mute_path()`]."
    )]
    #[cfg_attr(
        not(feature = "macos_12_0_0"),
        doc = "- If called on macOS 12.0+: uses `es_mute_path()`."
    )]
    /// - If called on macOS 10.15 or 11: uses [`es_mute_path_prefix()`] and [`es_mute_path_literal()`] accordingly.
    #[doc(alias = "es_mute_path")]
    #[doc(alias = "es_mute_path_prefix")]
    #[doc(alias = "es_mute_path_literal")]
    pub fn mute_path(&mut self, path: &OsStr, ty: es_mute_path_type_t) -> Result<(), ReturnError> {
        let cow = convert_byte_slice_to_cow_cstr(path.as_bytes());

        let res = versioned_call!(if cfg!(feature = "macos_12_0_0") && version >= (12, 0, 0) {
            // Safety: `cow` has a nul at the end
            unsafe { es_mute_path(self.as_mut(), cow.as_ptr(), ty) }
        } else {
            match ty {
                // Safety: `cow` has a nul at the end
                es_mute_path_type_t::ES_MUTE_PATH_TYPE_LITERAL => unsafe {
                    es_mute_path_literal(self.as_mut(), cow.as_ptr())
                },
                // Safety: `cow` has a nul at the end
                es_mute_path_type_t::ES_MUTE_PATH_TYPE_PREFIX => unsafe {
                    es_mute_path_prefix(self.as_mut(), cow.as_ptr())
                },
                _ => return Err(ReturnError::ApiUnavailable),
            }
        });

        res.ok()
    }

    /// Mute a path for a subset of event types.
    ///
    /// See [`es_mute_path_events`].
    ///
    /// # Note
    ///
    /// The C function takes a `const char * _Nonnull path`, which means it expects a nul-
    /// terminated string. Since the functions to gather such paths give [`OsString`]s (ex:
    /// [`Self::muted_paths_events`]), this method will truncate the given `path` to the first `\0`
    /// if it has one or add it itself if it does not (in which case there will be an allocation).
    ///
    /// Only available on macOS 12.0+.
    #[doc(alias = "es_mute_path_events")]
    #[cfg(feature = "macos_12_0_0")]
    pub fn mute_path_events(
        &mut self,
        path: &OsStr,
        ty: es_mute_path_type_t,
        events: &[es_event_type_t],
    ) -> Result<(), ReturnError> {
        if crate::version::is_version_or_more(12, 0, 0) == false {
            return Err(ReturnError::ApiUnavailable);
        }

        let cow = convert_byte_slice_to_cow_cstr(path.as_bytes());

        // Safety:
        // - `cow` has a nul at the end
        // - `.as_ptr()` and `.len()` are both called on `events` so they are in sync
        unsafe {
            es_mute_path_events(
                self.as_mut(),
                cow.as_ptr(),
                ty,
                events.as_ptr(),
                events.len(),
            )
        }
        .ok()
    }

    /// Unmute all paths for all events types.
    ///
    /// See [`es_unmute_all_paths()`].
    #[doc(alias = "es_unmute_all_paths")]
    #[inline(always)]
    pub fn unmute_all_paths(&mut self) -> Result<(), ReturnError> {
        // Safety: safe to call
        unsafe { es_unmute_all_paths(self.as_mut()) }.ok()
    }

    /// Unmute all target paths.
    ///
    /// See [`es_unmute_all_target_paths()`].
    ///
    /// Only available on macOS 13.0+.
    #[doc(alias = "es_unmute_all_target_paths")]
    #[cfg(feature = "macos_13_0_0")]
    #[inline(always)]
    pub fn unmute_all_target_paths(&mut self) -> Result<(), ReturnError> {
        if crate::version::is_version_or_more(13, 0, 0) == false {
            return Err(ReturnError::ApiUnavailable);
        }

        // Safety: safe to call
        unsafe { es_unmute_all_target_paths(self.as_mut()) }.ok()
    }

    /// Unmute a path for all event types.
    ///
    /// See [`es_unmute_path`].
    ///
    /// # Note
    ///
    /// The C function takes a `const char * _Nonnull path`, which means it expects a nul-terminated
    /// string. Since the functions to gather such paths give [`OsString`]s (ex: [`Self::muted_paths_events`]),
    /// this method will truncate the given `path` to the first `\0` if it has one or add it itself
    /// if it does not (in which case there will be an allocation).
    ///
    /// Only available on macOS 12.0+.
    #[doc(alias = "es_unmute_path")]
    #[cfg(feature = "macos_12_0_0")]
    #[inline(always)]
    pub fn unmute_path(&mut self, path: &OsStr, ty: es_mute_path_type_t) -> Result<(), ReturnError> {
        if crate::version::is_version_or_more(12, 0, 0) == false {
            return Err(ReturnError::ApiUnavailable);
        }

        let cow = convert_byte_slice_to_cow_cstr(path.as_bytes());

        // Safety: `cow` has a nul at the end
        unsafe { es_unmute_path(self.as_mut(), cow.as_ptr(), ty) }.ok()
    }

    /// Unmute a path for a subset of event types.
    ///
    /// See [`es_unmute_path_events`].
    ///
    /// # Note
    ///
    /// The C function takes a `const char * _Nonnull path`, which means it expects a nul-terminated
    /// string. Since the functions to gather such paths give [`OsString`]s (ex: [`Self::muted_paths_events`]),
    /// this method will truncate the given `path` to the first `\0` if it has one or add it itself
    /// if it does not (in which case there will be an allocation).
    ///
    /// Only available on macOS 12.0+.
    #[doc(alias = "es_unmute_path_events")]
    #[cfg(feature = "macos_12_0_0")]
    #[inline(always)]
    pub fn unmute_path_events(
        &mut self,
        path: &OsStr,
        ty: es_mute_path_type_t,
        events: &[es_event_type_t],
    ) -> Result<(), ReturnError> {
        if crate::version::is_version_or_more(12, 0, 0) == false {
            return Err(ReturnError::ApiUnavailable);
        }

        let cow = convert_byte_slice_to_cow_cstr(path.as_bytes());

        // Safety:
        // - `cow` has a nul at the end
        // - `.as_ptr()` and `.len()` are both called on `events` so they are in sync
        unsafe {
            es_unmute_path_events(
                self.as_mut(),
                cow.as_ptr(),
                ty,
                events.as_ptr(),
                events.len(),
            )
        }
        .ok()
    }

    /// List all muted paths.
    ///
    /// See [`es_muted_paths_events`].
    ///
    /// Only available on macOS 12.0+.
    #[doc(alias = "es_muted_paths_events")]
    #[doc(alias = "es_release_muted_paths")]
    #[cfg(feature = "macos_12_0_0")]
    pub fn muted_paths_events(&mut self) -> Result<Vec<MutedPath>, ReturnError> {
        if crate::version::is_version_or_more(12, 0, 0) == false {
            return Err(ReturnError::ApiUnavailable);
        }

        let data = to_vec_and_free!(
            self,
            es_muted_paths_events
            with custom free
        );

        let transformed = if data.is_null() {
            Vec::new()
        } else {
            // Safety: `data` is non-null we checked, let's hope Apple didn't ignore alignment
            let sl = unsafe { (*data).paths() };

            let mut v = Vec::with_capacity(sl.len());
            for mp in sl {
                v.push(MutedPath {
                    ty: mp.type_,
                    // Safety: if we were not lied to by ES, this is okay: the pointer is null if
                    // the size is zero, and valid if the size is not zero
                    events: unsafe { mp.events() }.into(),
                    // Safety: if we were not lied to by ES, this is okay: the pointer is null if
                    // the size is zero, and valid if the size is not zero
                    path: unsafe { mp.path.as_os_str() }.into(),
                });
            }

            // Safety:
            // - `data` is non null and hopefully valid for this
            // - there is no return to check
            unsafe { es_release_muted_paths(data) };

            v
        };

        Ok(transformed)
    }

    /// Invert the mute state of a given mute dimension.
    ///
    /// See [`es_invert_muting()`]
    ///
    /// Only available on macOS 13.0+.
    #[doc(alias = "es_invert_muting")]
    #[cfg(feature = "macos_13_0_0")]
    #[inline(always)]
    pub fn invert_muting(&mut self, mute_type: es_mute_inversion_type_t) -> Result<(), ReturnError> {
        if crate::version::is_version_or_more(13, 0, 0) == false {
            return Err(ReturnError::ApiUnavailable);
        }

        // Safety: safe to call
        unsafe { es_invert_muting(self.as_mut(), mute_type) }.ok()
    }

    /// Query mute inversion state
    ///
    /// See [`es_muting_inverted()`]
    ///
    /// Only available on macOS 13.0+.
    #[doc(alias = "es_muting_inverted")]
    #[cfg(feature = "macos_13_0_0")]
    #[inline(always)]
    pub fn muting_inverted(&mut self, mute_type: es_mute_inversion_type_t) -> Result<MuteInvertedType, MuteTypeError> {
        if crate::version::is_version_or_more(13, 0, 0) == false {
            return Err(MuteTypeError::ApiUnavailable);
        }

        // Safety: safe to call
        unsafe { es_muting_inverted(self.as_mut(), mute_type) }.ok()
    }

    /// Clear all cached results for **all** clients.
    ///
    /// See [`es_clear_cache()`].
    #[doc(alias = "es_clear_cache")]
    #[inline(always)]
    pub fn clear_cache(&mut self) -> Result<(), ClearCacheError> {
        // Safety: safe to call, our client is valid by construction
        unsafe { es_clear_cache(self.as_mut()) }.ok()
    }

    /// Delete a client and returns the result, whereas [`Drop`] ignores it.
    ///
    /// See [`es_delete_client()`].
    #[doc(alias = "es_delete_client")]
    #[inline(always)]
    pub fn delete(mut self) -> Result<(), ReturnError> {
        // Safety:
        // - We took ownership, this will only run once
        // - By construction our client is valid
        // - The result is checked
        let res = unsafe { es_delete_client(self.as_mut()) }.ok();

        // Avoid the double free since `self` would normally be dropped here
        std::mem::forget(self);

        res
    }
}

/// Private helper methods
impl Client<'_> {
    /// Mutable access to the inner client
    fn as_mut(&mut self) -> &mut es_client_t {
        // Safety: `inner` is valid by construction
        unsafe { self.inner.as_mut() }
    }
}

impl Drop for Client<'_> {
    /// Note: this implementation ignores the return value of [`es_delete_client`], use
    /// [`Client::delete()`] if you want to check it
    #[doc(alias = "es_delete_client")]
    #[inline(always)]
    fn drop(&mut self) {
        // Safety: Our client is non-null and valid by construction, and we are in `Drop` which will
        // only run once so no double free.
        let _ = unsafe { es_delete_client(self.as_mut()) };
    }
}
