//! [`EventCreate`]

use std::ffi::OsStr;

use endpoint_sec_sys::{es_destination_type_t, es_event_create_t, mode_t};

#[cfg(feature = "macos_10_15_1")]
use crate::Acl;
use crate::File;

/// Create a file system object event.
#[doc(alias = "es_event_create_t")]
pub struct EventCreate<'a> {
    /// Raw message
    pub(crate) raw: &'a es_event_create_t,
    /// Message version
    pub(crate) version: u32,
}

/// Represent a destination file for [`EventCreate`].
#[derive(Debug, PartialEq, Eq, Hash)]
#[doc(alias = "es_destination_type_t")]
pub enum EventCreateDestinationFile<'a> {
    /// The destination file already exist at the time of the event.
    ExistingFile(File<'a>),
    /// The destination doesn't exist at the time of the event.
    NewPath {
        /// The directory into which the file will be renamed.
        directory: File<'a>,
        /// The name of the new file that will be created.
        filename: &'a OsStr,
        /// The mode of the new file that will be created.
        mode: mode_t,
    },
}

impl<'a> EventCreate<'a> {
    /// Information about the destination of the new file
    #[inline(always)]
    pub fn destination(&self) -> Option<EventCreateDestinationFile<'a>> {
        match self.raw.destination_type {
            es_destination_type_t::ES_DESTINATION_TYPE_EXISTING_FILE => {
                Some(EventCreateDestinationFile::ExistingFile(
                    // Safety: Safe as we select the union field corresponding to that type.
                    File::new(unsafe { self.raw.destination.existing_file.as_ref() }),
                ))
            },
            es_destination_type_t::ES_DESTINATION_TYPE_NEW_PATH => {
                // Safety: Safe as we select the union fields corresponding to that type.
                let new_path = unsafe { &self.raw.destination.new_path };
                Some(EventCreateDestinationFile::NewPath {
                    // Safety: 'a tied to self, object obtained through ES
                    directory: File::new(unsafe { new_path.dir() }),
                    // Safety: 'a tied to self, object obtained through ES
                    filename: unsafe { new_path.filename.as_os_str() },
                    mode: new_path.mode,
                })
            },
            _ => None,
        }
    }

    /// The ACL that the new file system object got or gets created with.
    ///
    /// May be `None` if the file system object gets created without ACL.
    #[inline(always)]
    #[cfg(feature = "macos_10_15_1")]
    pub fn acl(&self) -> Option<Acl<'a>> {
        if self.version < 2 {
            return None;
        }

        // Safety: we checked the version is >= 2
        Acl::from_raw(unsafe { self.raw.anon_1.anon_0.acl })
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventCreate<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventCreate<'_> {}

impl_debug_eq_hash_with_functions!(EventCreate<'a> with version; destination, #[cfg(feature = "macos_10_15_1")] acl);
