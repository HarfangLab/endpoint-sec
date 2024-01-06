//! [`EventSu`]

use std::ffi::OsStr;

use endpoint_sec_sys::{es_event_su_t, es_string_token_t};
use libc::uid_t;

/// A `su` policy decision event.
#[doc(alias = "es_event_su_t")]
pub struct EventSu<'a> {
    /// The raw event.
    pub(crate) raw: &'a es_event_su_t,
}

impl<'a> EventSu<'a> {
    /// True iff su was successful.
    #[inline(always)]
    pub fn success(&self) -> bool {
        self.raw.success
    }

    /// If `success` is `false`, a failure message is contained in this field.
    #[inline(always)]
    pub fn failure_message(&self) -> Option<&'a OsStr> {
        match self.success() {
            false => None,
            // Safety: checked for `success` value, lifetime matches that of event
            true => Some(unsafe { self.raw.failure_message.as_os_str() }),
        }
    }

    /// The uid of the user who initiated the su.
    #[inline(always)]
    pub fn from_uid(&self) -> uid_t {
        self.raw.from_uid
    }

    /// The name of the user who initiated the su.
    #[inline(always)]
    pub fn from_username(&self) -> &'a OsStr {
        // Safety: lifetime matches that of message
        unsafe { self.raw.from_username.as_os_str() }
    }

    /// True iff su was successful, Describes whether or not the to_uid is interpretable
    #[inline(always)]
    pub fn has_to_uid(&self) -> bool {
        self.raw.has_to_uid
    }

    /// If success, the user ID that is going to be substituted
    #[inline(always)]
    pub fn to_uid(&self) -> Option<uid_t> {
        // Safety: checked for success and `has_to_uid`
        (self.success() && self.has_to_uid()).then(|| unsafe { self.raw.to_uid.uid })
    }

    /// If success, the user name that is going to be substituted
    #[inline(always)]
    pub fn to_username(&self) -> Option<&'a OsStr> {
        match self.success() {
            false => None,
            // Safety: checked for success, lifetime matches that of event
            true => unsafe { Some(self.raw.to_username.as_os_str()) },
        }
    }

    /// If success, the shell that is going to be executed
    #[inline(always)]
    pub fn shell(&self) -> Option<&'a OsStr> {
        match self.success() {
            false => None,
            // Safety: checked for success, lifetime matches that of event
            true => unsafe { Some(self.raw.shell.as_os_str()) },
        }
    }

    /// Argument count
    #[inline(always)]
    pub fn arg_count(&self) -> usize {
        self.raw.argc
    }

    /// Environment count
    #[inline(always)]
    pub fn env_count(&self) -> usize {
        self.raw.env_count
    }

    /// If success, the arguments are passed into to the shell
    #[inline(always)]
    pub fn args<'e>(&'e self) -> Option<SuArgs<'e, 'a>> {
        match self.success() {
            false => None,
            true => Some(SuArgs::new(self)),
        }
    }

    /// If success, list of environment variables that is going to be substituted
    #[inline(always)]
    pub fn envs<'e>(&'e self) -> Option<SuEnvs<'e, 'a>> {
        match self.success() {
            false => None,
            true => Some(SuEnvs::new(self)),
        }
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventSu<'_> {}

impl_debug_eq_hash_with_functions!(EventSu<'a>; success, failure_message, from_uid, from_username, to_uid, to_username, shell, arg_count, env_count);

/// Read the `idx` arg of `raw`
///
/// # Safety
///
/// Must be called with a valid event for which `idx` is in range `0..raw.argc`
unsafe fn read_nth_arg(raw: &es_event_su_t, idx: usize) -> es_string_token_t {
    std::ptr::read(raw.argv.add(idx))
}

/// Read the `idx` env of `raw`
///
/// # Safety
///
/// Must be called with a valid event for which `idx` is in range `0..raw.env_count`
unsafe fn read_nth_env(raw: &es_event_su_t, idx: usize) -> es_string_token_t {
    std::ptr::read(raw.env.add(idx))
}

make_event_data_iterator!(
    EventSu;
    /// Iterator over the arguments of an [`EventSu`]
    SuArgs with arg_count (usize);
    &'raw OsStr;
    read_nth_arg,
    super::as_os_str,
);

make_event_data_iterator!(
    EventSu;
    /// Iterator over the environment of an [`EventSu`]
    SuEnvs with env_count (usize);
    &'raw OsStr;
    read_nth_env,
    super::as_os_str,
);
