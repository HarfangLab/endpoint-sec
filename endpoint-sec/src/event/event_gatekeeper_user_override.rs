//! [`EventGatekeeperUserOverride`]

use std::ffi::OsStr;

use endpoint_sec_sys::{es_event_gatekeeper_user_override_t, es_gatekeeper_user_override_file_type_t, es_signed_file_info_t};

use crate::File;

/// Notification for a gatekeeper_user_override event.
///
/// This event type does not support caching (notify-only).
///
/// Hashes are calculated in usermode by Gatekeeper. There is no guarantee that
/// any other program including the kernel will observe the same file at the
/// reported path. Furthermore, there is no guarantee that the CDHash is valid
/// or that it matches the containing binary.
#[doc(alias = "es_event_gatekeeper_user_override_t")]
pub struct EventGatekeeperUserOverride<'a> {
    /// Raw event
    pub(super) raw: &'a es_event_gatekeeper_user_override_t,
}

impl<'a> EventGatekeeperUserOverride<'a> {
    /// Describes the target file that is being overridden by the user.
    ///
    /// If Endpoint security can't lookup the file at event submission it will
    /// emit a path instead of a [`File`].
    pub fn file(&self) -> Option<GatekeeperFile<'a>> {
        match self.raw.file_type {
            es_gatekeeper_user_override_file_type_t::ES_GATEKEEPER_USER_OVERRIDE_FILE_TYPE_PATH => {
                // Safety: Union access (file_path) is allowed as file_type
                // indicates this field was used to construct this event.
                //
                // 'a tied to self, object obtained through ES
                let file_path = unsafe { self.raw.file.file_path.as_os_str() };
                Some(GatekeeperFile::Path(file_path))
            },
            es_gatekeeper_user_override_file_type_t::ES_GATEKEEPER_USER_OVERRIDE_FILE_TYPE_FILE => {
                // Safety: Union access (file_path) is allowed as file_type
                // indicates this field was used to construct this event.
                //
                // 'a tied to self, object obtained through ES
                let file = unsafe { self.raw.file.file.as_ref() };
                Some(GatekeeperFile::File(File::new(file)))
            },
            _ => None,
        }
    }

    /// SHA256 of the file.
    ///
    /// Provided if the filesize is less than 100MB.
    #[inline(always)]
    pub fn sha256(&self) -> &[u8; 32] {
        // Safety: 'a tied to self, object obtained through ES
        unsafe {
            &*self.raw.sha256
        }
    }

    /// Signing Information, available if the file has been signed.
    #[inline(always)]
    pub fn signing_info(&self) -> Option<SignedFileInfo<'_>> {
        // Safety: 'a tied to self, object obtained through ES
        let signing_info = unsafe { self.raw.signing_info()? };
        Some(SignedFileInfo::new(signing_info))
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventGatekeeperUserOverride<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventGatekeeperUserOverride<'_> {}

impl_debug_eq_hash_with_functions!(EventGatekeeperUserOverride<'a>; file, sha256, signing_info);

/// The file being overridden by a user.
#[derive(Debug, PartialEq, Hash)]
pub enum GatekeeperFile<'a> {
    /// Endpoint Security couldn't lookup the file, and emitted a path.
    Path(&'a OsStr),
    /// The full information of the file being overridden.
    File(File<'a>),
}


/// Information from a signed file.
///
/// If the file is a multiarchitecture binary, only the signing information for
/// the native host architecture is reported. I.e. the CDHash from the AArch64
/// slice if the host is AArch64.
pub struct SignedFileInfo<'a> {
    /// Raw event
    raw: &'a es_signed_file_info_t,
}

impl<'a> SignedFileInfo<'a> {
    /// Create a new [`SignedFileInfo`] instance.
    fn new(raw: &es_signed_file_info_t) -> SignedFileInfo<'_> {
        SignedFileInfo { raw }
    }

    /// Code Directory Hash
    #[inline(always)]
    pub fn cdhash(&self) -> &'a [u8; 20] {
        &self.raw.cdhash
    }

    /// Signing Identifier, if available in the signing information.
    #[inline(always)]
    pub fn signing_id(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe {
            self.raw.signing_id.as_os_str()
        }
    }

    /// Team Identifier, if available in the signing information.
    #[inline(always)]
    pub fn team_id(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe {
            self.raw.team_id.as_os_str()
        }
    }
}

impl_debug_eq_hash_with_functions!(SignedFileInfo<'a>; cdhash, signing_id, team_id);
