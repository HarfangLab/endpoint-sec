//! [`EventRename`]

use std::ffi::OsStr;

use endpoint_sec_sys::{es_destination_type_t, es_event_rename_t};

use crate::File;

/// Rename a file system object event.
#[doc(alias = "es_event_rename_t")]
pub struct EventRename<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_rename_t,
}

/// Represent a destination file for [`EventRename`].
#[derive(Debug, PartialEq, Eq, Hash)]
#[doc(alias = "es_destination_type_t")]
pub enum EventRenameDestinationFile<'a> {
    /// The destination file already exist at the time of the event.
    ExistingFile(File<'a>),
    /// The destination doesn't exist at the time of the event.
    NewPath {
        /// The directory into which the file will be renamed.
        directory: File<'a>,
        /// The name of the new file that will be created.
        filename: &'a OsStr,
    },
}

impl<'a> EventRename<'a> {
    /// The source file that is being renamed.
    #[inline(always)]
    pub fn source(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.source() })
    }

    /// Information about the destination of the renamed file.
    #[inline(always)]
    pub fn destination(&self) -> Option<EventRenameDestinationFile<'a>> {
        match self.raw.destination_type {
            es_destination_type_t::ES_DESTINATION_TYPE_EXISTING_FILE => {
                // Safety: Safe as we select the union field corresponding to that type.
                Some(EventRenameDestinationFile::ExistingFile(unsafe {
                    File::new(self.raw.destination.existing_file.as_ref())
                }))
            },
            es_destination_type_t::ES_DESTINATION_TYPE_NEW_PATH => {
                // Safety: Safe as we select the union fields corresponding to that type.
                let new_path = unsafe { &self.raw.destination.new_path };
                Some(EventRenameDestinationFile::NewPath {
                    // Safety: 'a tied to self, object obtained through ES
                    directory: File::new(unsafe { new_path.dir() }),
                    // Safety: 'a tied to self, object obtained through ES
                    filename: unsafe { new_path.filename.as_os_str() },
                })
            },
            _ => None,
        }
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventRename<'_> {}

impl_debug_eq_hash_with_functions!(EventRename<'a>; source, destination);
