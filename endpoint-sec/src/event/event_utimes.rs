//! [`EventUTimes`]

use std::time::SystemTime;

use endpoint_sec_sys::es_event_utimes_t;

use crate::{utils, File};

///  Change file access and modification times (e.g. via utimes(2))
#[doc(alias = "es_event_utimes_t")]
pub struct EventUTimes<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_utimes_t,
}

impl<'a> EventUTimes<'a> {
    /// The path which will have its times modified.
    #[inline(always)]
    pub fn target(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.target() })
    }

    /// The desired new access time, in its raw form.
    ///
    /// See also [`Self::atime()`]
    #[inline(always)]
    pub fn raw_atime(&self) -> endpoint_sec_sys::timespec {
        self.raw.atime
    }

    /// The desired new access time.
    ///
    /// See also [`Self::raw_atime()`]
    #[inline(always)]
    pub fn atime(&self) -> SystemTime {
        let dur = utils::convert_timespec_to_duration(self.raw.atime);
        SystemTime::UNIX_EPOCH + dur
    }

    /// The desired new modification time, in its raw form.
    ///
    /// See also [`Self::mtime()`]
    #[inline(always)]
    pub fn raw_mtime(&self) -> endpoint_sec_sys::timespec {
        self.raw.mtime
    }

    /// The desired new modification time.
    ///
    /// See also [`Self::raw_mtime()`]
    #[inline(always)]
    pub fn mtime(&self) -> SystemTime {
        let dur = utils::convert_timespec_to_duration(self.raw.mtime);
        SystemTime::UNIX_EPOCH + dur
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventUTimes<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventUTimes<'_> {}

impl_debug_eq_hash_with_functions!(EventUTimes<'a>; target, atime, mtime);
