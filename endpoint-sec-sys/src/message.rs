//! Corresponding header: `EndpointSecurity/ESMessage.h`
//!
//! Messages for an event are received when clients are subscribed to their related event, either
//! auth or notify.

// Types and methods should be added in the same order as they are in the original header to make
// maintenance easier.

use core::hash::Hash;
use core::mem::ManuallyDrop;
pub use std::os::raw::c_int;

#[cfg(feature = "macos_13_0_0")]
pub use libc::{cpu_subtype_t, cpu_type_t};
pub use libc::{dev_t, gid_t, mode_t, pid_t, stat, statfs, timespec, timeval, uid_t};
use objc2_encode::{Encoding, RefEncode};

#[cfg(feature = "macos_10_15_4")]
use super::es_proc_check_type_t;
#[cfg(feature = "macos_10_15_1")]
use super::{acl_t, es_set_or_clear_t};
use super::{
    attrlist, audit_token_t, es_action_type_t, es_auth_result_t, es_event_id_t, es_event_type_t, es_result_type_t,
    es_string_token_t, es_token_t, user_addr_t, user_size_t, ShouldNotBeNull,
};
#[cfg(feature = "macos_13_0_0")]
use super::{es_address_type_t, es_authentication_type_t};

/// Provides the [`stat`][struct@stat] information and path to a file that relates to a security
/// event. The path may be truncated, which is indicated by the `path_truncated` flag.
///
/// For the FAT family of filesystems the `stat.st_ino` field is set to 999999999 for empty files.
///
/// For files with a link count greater than 1, the absolute path given may not be the only absolute
/// path that exists, and which hard link the emitted path points to is undefined.
///
/// Overlong paths are truncated at a maximum length that currently is 16K, though that number is
/// not considered API and may change at any time.
#[repr(C)]
pub struct es_file_t {
    /// Absolute path of the file
    pub path: es_string_token_t,
    /// Indicates if the `path` field was truncated
    pub path_truncated: bool,
    /// Informations about the file. See `man 2 stat` for details
    pub stat: stat,
}

/// Information related to a thread
#[cfg(feature = "macos_11_0_0")]
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct es_thread_t {
    /// Unique of the thread
    pub thread_id: u64,
}

/// Information related to a process. This is used both for describing processes that performed an
/// action (e.g. in the case of the [`es_message_t.process`] field, or are targets of an action (e.g.
/// for exec events this describes the new process being executed, for signal events this describes
/// the process that will receive the signal).
///
/// Values such as PID, UID, GID, etc. can be extracted from audit tokens via API in `libbsm.h`.
///
/// ### Multiple ES clients
///
/// Clients should take caution when processing events where `is_es_client` is true. If multiple ES
/// clients exist, actions taken by one client could trigger additional actions by the other client,
/// causing a potentially infinite cycle.
///
/// ### Code signing
///
/// Fields related to code signing in the target `es_process_t` reflect the state of the process
/// at the time the message is generated. In the specific case of exec, this is after the exec
/// completed in the kernel, but before any code in the process has started executing. At that
/// point, XNU has validated the signature itself and has verified that the `CDHash` is correct
/// in that the hash of all the individual page hashes in the Code Directory matches the signed
/// `CDHash`, essentially verifying the signature was not tampered with. However, individual page
/// hashes are not verified by XNU until the corresponding pages are paged in once they are accessed
/// while the binary executes. It is not until the individual pages are paged in that XNU determines
/// if a binary has been tampered with and will update the code signing flags accordingly.
///
/// Endpoint Security provides clients the current state of the CS flags in the `codesigning_flags`
/// member of the `es_process_t` struct. The `CS_VALID` bit in the `codesigning_flags` means that
/// everything the kernel has validated **up to that point in time** was valid, but not that there
/// has been a full validation of all the pages in the executable file. If page content has been
/// tampered with in the executable, we won't know until that page is paged in. At that time, the
/// process will have its `CS_VALID` bit cleared and, if `CS_KILL` is set, the process will be
/// killed, preventing any tampered code from being executed.
///
/// `CS_KILL` is generally set for platform binaries and for binaries having opted into the hardened
/// runtime. An ES client wishing to detect tampered code before it is paged in, for example at
/// exec time, can use the Security framework to do so, but should be cautious of the potentially
/// significant performance cost. The Endpoint Security subsystem itself has no role in verifying
/// the validity of code signatures.
#[repr(C)]
pub struct es_process_t {
    /// Audit token of the process
    pub audit_token: audit_token_t,
    /// Parent pid of the process. It is recommended to instead use the `parent_audit_token` field.
    pub ppid: pid_t,
    /// Original ppid of the process. This field stays constant even in the event this process is
    /// reparented.
    pub original_ppid: pid_t,
    /// Process group id the process belongs to
    pub group_id: pid_t,
    /// Session id the process belongs to
    pub session_id: pid_t,
    /// Code signing flags of the process. The values for these flags can be found in the include
    /// file `cs_blobs.h` (`#include <kern/cs_blobs.h>`).
    pub codesigning_flags: u32,
    pub is_platform_binary: bool,
    /// Indicates this process has the Endpoint Security entitlement
    pub is_es_client: bool,
    /// The code directory hash of the code signature associated with this process
    pub cdhash: [u8; 20],
    /// The signing id of the code signature associated with this process
    pub signing_id: es_string_token_t,
    /// The team id of the code signature associated with this process
    pub team_id: es_string_token_t,
    /// The executable file that is executing in this process.
    ///
    /// **Non**-nullable
    pub executable: ShouldNotBeNull<es_file_t>,
    /// The TTY this process is associated with, or NULL if the process does not have an associated
    /// TTY.
    ///
    /// Field available only if message version >= 2.
    #[cfg(feature = "macos_10_15_1")]
    pub tty: *mut es_file_t,
    /// Process start time, i.e. time of fork creating this process.
    ///
    /// Field available only if message version >= 3.
    #[cfg(feature = "macos_10_15_4")]
    pub start_time: timeval,
    /// Audit token of the process responsible for this process, which may be the process itself in
    /// case there is no responsible process or the responsible process has already exited.
    ///
    /// Field available only if message version >= 4.
    #[cfg(feature = "macos_11_0_0")]
    pub responsible_audit_token: audit_token_t,
    /// Audit token of the parent process.
    ///
    /// Field available only if message version >= 4.
    #[cfg(feature = "macos_11_0_0")]
    pub parent_audit_token: audit_token_t,
}

should_not_be_null_fields!(es_process_t; executable -> es_file_t);
#[cfg(feature = "macos_10_15_1")]
null_fields!(es_process_t; tty -> es_file_t);

/// Machine-specific thread state as used by `thread_create_running` and other Mach API functions.
///
/// The `size` subfield of the `state` field is in bytes, NOT `natural_t` units. Definitions for
/// working with thread state can be found in the include file `mach/thread_status.h` and
/// corresponding machine-dependent headers.
#[cfg(feature = "macos_11_0_0")]
#[repr(C)]
pub struct es_thread_state_t {
    /// Representation of the machine-specific thread state
    pub flavor: c_int,
    /// Machine-specific thread state, equivalent to `thread_state_t` in Mach APIs
    pub state: es_token_t,
}

/// An open file descriptor
#[cfg(feature = "macos_11_0_0")]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct es_fd_t {
    /// File descriptor number
    pub fd: i32,
    /// File descriptor type, as `libproc` fdtype
    pub fdtype: u32,
    /// Available if `fdtype` is [`Self::PROX_FDTYPE_PIPE`]
    pub anon_0: es_fd_t_anon_0,
}

#[cfg(feature = "macos_11_0_0")]
impl es_fd_t {
    /// Helper constant when checking if `anon_0` is valid by looking at `fdtype`
    pub const PROX_FDTYPE_PIPE: u32 = 6;

    /// Access the `pipe` member of [`es_fd_t_anon_0`] if `fdtype` is [`Self::PROX_FDTYPE_PIPE`].
    ///
    /// # Safety
    ///
    /// The `fdtype` and `anon_0` fields must be kept in sync.
    pub unsafe fn pipe(&self) -> Option<es_fd_t_anon_0_pipe> {
        if self.fdtype == Self::PROX_FDTYPE_PIPE {
            // Safety: we checked `fdtype` for the correct value just before and the caller
            // guarantees the fields are synced
            Some(unsafe { self.anon_0.pipe })
        } else {
            None
        }
    }
}

/// See [`es_fd_t_anon_0.anon_0`]
#[cfg(feature = "macos_11_0_0")]
#[repr(C)]
#[derive(Copy, Clone)]
pub union es_fd_t_anon_0 {
    pub pipe: es_fd_t_anon_0_pipe,
}

/// Pipe information available in [`es_fd_t`] if the `fdtype` field is `PROX_FDTYPE_PIPE`
///
/// See [`es_fd_t_anon_0_pipe.pipe`]
#[cfg(feature = "macos_11_0_0")]
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct es_fd_t_anon_0_pipe {
    /// Unique id of the pipe for correlation with other file descriptors pointing to the same or
    /// other end of the same pipe
    pub pipe_id: u64,
}

#[cfg(feature = "macos_13_0_0")]
ffi_wrap_enum!(
    /// Type of launch item.
    ///
    /// See [`es_btm_launch_item_t`]
    es_btm_item_type_t(u32);

    == MACOS_13_0_0;
    ES_BTM_ITEM_TYPE_USER_ITEM = 0,
    ES_BTM_ITEM_TYPE_APP = 1,
    ES_BTM_ITEM_TYPE_LOGIN_ITEM = 2,
    ES_BTM_ITEM_TYPE_AGENT = 3,
    --
    ES_BTM_ITEM_TYPE_DAEMON = 4,
);

/// Structure describing a BTM launch item
#[cfg(feature = "macos_13_0_0")]
#[repr(C)]
pub struct es_btm_launch_item_t {
    /// Type of launch item.
    pub item_type: es_btm_item_type_t,
    /// True only if item is a legacy plist.
    pub legacy: bool,
    /// True only if item is managed by MDM.
    pub managed: bool,
    /// User ID for the item (may be user `nobody` (`-2`)).
    pub uid: uid_t,
    /// URL for item.
    ///
    /// If a file URL describing a relative path, it is relative to `app_url`.
    pub item_url: es_string_token_t,
    /// Optional. URL for app the item is attributed to.
    // NOTE: find out how optionality is modeled. Empty string ? Linked to an enum member ?
    pub app_url: es_string_token_t,
}

/// Execute a new process
///
/// Process arguments, environment variables and file descriptors are packed, use API functions
/// to access them: [`es_exec_arg()`], [`es_exec_arg_count()`], [`es_exec_env()`],
/// [`es_exec_env_count()`],
#[cfg_attr(feature = "macos_11_0_0", doc = "[`es_exec_fd()`] and [`es_exec_fd_count()`].")]
#[cfg_attr(not(feature = "macos_11_0_0"), doc = "`es_exec_fd()` and `es_exec_fd_count()`.")]
///
/// The API may only return descriptions for a subset of open file descriptors; how many and
/// which file descriptors are available as part of exec events is not considered API and can change
/// in future releases.
///
/// The CPU type and subtype correspond to `CPU_TYPE_*` and `CPU_SUBTYPE_*` macros defined in
/// `<mach/machine.h>`.
///
/// Fields related to code signing in `target` represent kernel state for the process at the
/// point in time the exec has completed, but the binary has not started running yet. Because code
/// pages are not validated until they are paged in, this means that modifications to code pages
/// would not have been detected yet at this point. For a more thorough explanation, please see the
/// documentation for [`es_process_t`].
///
/// There are two [`es_process_t`] fields that are represented in an [`es_message_t`] that
/// contains an `es_event_exec_t`. The `es_process_t` within the `es_message_t` struct (named
/// `process`) contains information about the program that calls `execve(2)` (or `posix_spawn(2)`).
/// This information is gathered prior to the program being replaced. The other `es_process_t`,
/// within the `es_event_exec_t` struct (named `target`), contains information about the program
/// after the image has been replaced by `execve(2)` (or `posix_spawn(2)`). This means that both
/// `es_process_t` structs refer to the same process, but not necessarily the same program. Also,
/// note that the `audit_token_t` structs contained in the two different `es_process_t` structs
/// will not be identical: the `pidversion` field will be updated, and the UID/GID values may be
/// different if the new program had `setuid`/`setgid` permission bits set.
///
/// Cache key for this event type: `(process executable file, target executable file)`.
#[repr(C)]
// 10.15.0
pub struct es_event_exec_t {
    /// The new process that is being executed
    pub target: ShouldNotBeNull<es_process_t>,
    /// This field must not be accessed directly (see notes)
    #[cfg(not(feature = "macos_13_3_0"))]
    _reserved0: es_token_t,
    /// The exec path passed up to dyld, before symlink resolution. This is the path argument
    /// to `execve(2)` or `posix_spawn(2)`, or the interpreter from the shebang line for scripts run
    /// through the shell script image activator.
    ///
    /// Field available only if message version >= 7.
    #[cfg(feature = "macos_13_3_0")]
    pub dyld_exec_path: es_string_token_t,
    /// See variants of union
    pub anon_0: es_event_exec_t_anon_0,
}

should_not_be_null_fields!(es_event_exec_t; target -> es_process_t);

/// See [`es_event_exec_t.anon_0`]
#[repr(C)]
pub union es_event_exec_t_anon_0 {
    _reserved: [u8; 64],
    #[cfg(feature = "macos_10_15_1")]
    pub anon_0: ManuallyDrop<es_event_exec_t_anon_0_anon_0>,
}

/// See [`es_event_exec_t_anon_0.anon_0`]
#[repr(C)]
pub struct es_event_exec_t_anon_0_anon_0 {
    /// Script being executed by interpreter. This field is only valid if a script was executed
    /// directly and not as an argument to the interpreter (e.g. `./foo.sh` not `/bin/sh ./foo.sh`)
    ///
    /// Field available only if message version >= 2.
    #[cfg(feature = "macos_10_15_1")]
    pub script: *mut es_file_t,
    /// Current working directory at exec time.
    ///
    /// Field available only if message version >= 3.
    #[cfg(feature = "macos_10_15_4")]
    pub cwd: ShouldNotBeNull<es_file_t>,
    /// Highest open file descriptor after the exec completed. This number is equal to or
    /// larger than the highest number of file descriptors available via [`es_exec_fd_count()`] and
    /// [`es_exec_fd()`], in which case EndpointSecurity has capped the number of file descriptors
    /// available in the message. File descriptors for open files are not necessarily contiguous.
    /// The exact number of open file descriptors is not available.
    ///
    /// Field available only if message version >= 4.
    #[cfg(feature = "macos_11_0_0")]
    pub last_fd: c_int,

    /// The CPU type of the executable image which is being executed. In case of translation, this
    /// may be a different architecture than the one of the system.
    ///
    /// Field available only if message version >= 6.
    #[cfg(feature = "macos_13_0_0")]
    pub image_cputype: cpu_type_t,
    /// The CPU subtype of the executable image.
    ///
    /// Field available only if message version >= 6.
    #[cfg(feature = "macos_13_0_0")]
    pub image_cpusubtype: cpu_subtype_t,
}

#[cfg(feature = "macos_10_15_4")]
should_not_be_null_fields!(es_event_exec_t_anon_0_anon_0; cwd -> es_file_t);
#[cfg(feature = "macos_10_15_1")]
null_fields!(es_event_exec_t_anon_0_anon_0; script -> es_file_t);

/// Open a file system object.
///
/// The `fflag` field represents the mask as applied by the kernel, not as represented by
/// typical `open(2)` `oflag` values. When responding to `ES_EVENT_TYPE_AUTH_OPEN` events using
/// [`es_respond_flags_result()`][super::es_respond_flags_result], ensure that the same `FFLAG`
/// values are used (e.g. `FREAD`, `FWRITE` instead of `O_RDONLY`, `O_RDWR`, etc...).
///
/// Cache key for this event type: `(process executable file, file that will be opened)`.
///
/// See `fcntl.h`
#[repr(C)]
// 10.15.0
pub struct es_event_open_t {
    /// The desired flags to be used when opening `file` (see note)
    pub fflag: i32,
    /// The file that will be opened
    pub file: ShouldNotBeNull<es_file_t>,
    _reserved: [u8; 64],
}

should_not_be_null_fields!(es_event_open_t; file -> es_file_t);

/// Load a kernel extension
///
/// This event type does not support caching.
#[repr(C)]
// 10.15.0
pub struct es_event_kextload_t {
    /// The signing identifier of the kext being loaded
    pub identifier: es_string_token_t,
    _reserved: [u8; 64],
}

/// Unload a kernel extension
///
/// This event type does not support caching (notify-only).
#[repr(C)]
// 10.15.0
pub struct es_event_kextunload_t {
    /// The signing identifier of the kext being unloaded
    pub identifier: es_string_token_t,
    _reserved: [u8; 64],
}

/// Unlink a file system object.
///
/// This event can fire multiple times for a single syscall, for example when the syscall has to be
/// retried due to racing VFS operations.
///
/// This event type does not support caching.
#[repr(C)]
// 10.15.0
pub struct es_event_unlink_t {
    /// The object that will be removed
    pub target: ShouldNotBeNull<es_file_t>,
    /// The parent directory of the `target` file system object
    pub parent_dir: ShouldNotBeNull<es_file_t>,
    _reserved: [u8; 64],
}

should_not_be_null_fields!(es_event_unlink_t; target -> es_file_t, parent_dir -> es_file_t);

/// Memory map a file
///
/// Cache key for this event type: `(process executable file, source file)`.
#[repr(C)]
// 10.15.0
pub struct es_event_mmap_t {
    /// The protection (region accessibility) value
    pub protection: i32,
    /// The maximum allowed protection value the operating system will respect
    pub max_protection: i32,
    /// The type and attributes of the mapped file
    pub flags: i32,
    /// The offset into `source` that will be mapped
    pub file_pos: u64,
    /// The file system object being mapped
    pub source: ShouldNotBeNull<es_file_t>,
    _reserved: [u8; 64],
}

should_not_be_null_fields!(es_event_mmap_t; source -> es_file_t);

/// Link to a file
///
/// This event type does not support caching.
#[repr(C)]
// 10.15.0
pub struct es_event_link_t {
    /// The existing object to which a hard link will be created
    pub source: ShouldNotBeNull<es_file_t>,
    /// The directory in which the link will be created
    pub target_dir: ShouldNotBeNull<es_file_t>,
    /// The name of the new object linked to `source`
    pub target_filename: es_string_token_t,
    _reserved: [u8; 64],
}

should_not_be_null_fields!(es_event_link_t; source -> es_file_t, target_dir -> es_file_t);

/// Mount a file system
///
/// Cache key for this event type: `(process executable file, mount point)`.
#[repr(C)]
// 10.15.0
pub struct es_event_mount_t {
    /// The file system stats for the file system being mounted
    pub statfs: ShouldNotBeNull<statfs>,
    _reserved: [u8; 64],
}

should_not_be_null_fields!(es_event_mount_t; statfs -> statfs);

/// Unmount a file system
///
/// This event type does not support caching (notify-only).
#[repr(C)]
// 10.15.0
pub struct es_event_unmount_t {
    /// The file system stats for the file system being unmounted
    pub statfs: ShouldNotBeNull<statfs>,
    _reserved: [u8; 64],
}

should_not_be_null_fields!(es_event_unmount_t; statfs -> statfs);

/// Remount a file system
///
/// This event type does not support caching.
#[cfg(feature = "macos_10_15_1")]
#[repr(C)]
pub struct es_event_remount_t {
    /// The file system stats for the file system being remounted
    pub statfs: ShouldNotBeNull<statfs>,
    _reserved: [u8; 64],
}

#[cfg(feature = "macos_10_15_1")]
should_not_be_null_fields!(es_event_remount_t; statfs -> statfs);

/// Fork a new process
///
/// This event type does not support caching (notify-only).
#[repr(C)]
// 10.15.0
pub struct es_event_fork_t {
    /// The child process that was created
    pub child: ShouldNotBeNull<es_process_t>,
    _reserved: [u8; 64],
}

should_not_be_null_fields!(es_event_fork_t; child -> es_process_t);

/// Control protection of pages
///
/// This event type does not support caching.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
// 10.15.0
pub struct es_event_mprotect_t {
    /// The desired new protection value
    pub protection: i32,
    /// The base address to which the protection value will apply
    pub address: user_addr_t,
    /// The size of the memory region the protection value will apply
    pub size: user_size_t,
    _reserved: [u8; 64],
}

/// Send a signal to a process.
///
/// This event will not fire if a process sends a signal to itself.
///
/// Cache key for this event type: `(process executable file, target process executable file)`.
#[repr(C)]
// 10.15.0
pub struct es_event_signal_t {
    /// The signal number to be delivered
    pub sig: c_int,
    /// The process that will receive the signal
    pub target: ShouldNotBeNull<es_process_t>,
    _reserved: [u8; 64],
}

should_not_be_null_fields!(es_event_signal_t; target -> es_process_t);

ffi_wrap_enum!(
    es_destination_type_t(u32);

    == MACOS_10_15_0;
    ES_DESTINATION_TYPE_EXISTING_FILE = 0,
    --
    ES_DESTINATION_TYPE_NEW_PATH = 1,
);

/// Rename a file system object.
///
/// The `destination_type` field describes which member in the `destination` union should
/// accessed. `ES_DESTINATION_TYPE_EXISTING_FILE` means that `existing_file` should be used,
/// `ES_DESTINATION_TYPE_NEW_PATH` means that the `new_path` struct should be used.
///
/// This event can fire multiple times for a single syscall, for example when the syscall has to be
/// retried due to racing VFS operations.
///
/// This event type does not support caching.
#[repr(C)]
// 10.15.0
pub struct es_event_rename_t {
    /// The source file that is being renamed
    pub source: ShouldNotBeNull<es_file_t>,
    /// Whether or not the destination refers to an existing or new file
    pub destination_type: es_destination_type_t,
    /// Information about the destination of the renamed file (see note)
    pub destination: es_event_rename_t_anon_0,
    _reserved: [u8; 64],
}

should_not_be_null_fields!(es_event_rename_t; source -> es_file_t);

/// See [`es_event_rename_t`]
#[repr(C)]
pub union es_event_rename_t_anon_0 {
    /// The destination file that will be overwritten
    pub existing_file: ShouldNotBeNull<es_file_t>,
    /// Information regarding the destination of a newly created file
    pub new_path: ManuallyDrop<es_event_rename_t_anon_0_anon_0>,
}

/// See [`es_event_rename_t_anon_0`]
#[repr(C)]
pub struct es_event_rename_t_anon_0_anon_0 {
    /// The directory into which the file will be renamed
    pub dir: ShouldNotBeNull<es_file_t>,
    /// The name of the new file that will be created
    pub filename: es_string_token_t,
}

should_not_be_null_fields!(es_event_rename_t_anon_0_anon_0; dir -> es_file_t);

/// Set an extended attribute
///
/// This event type does not support caching.
#[repr(C)]
// 10.15.0
pub struct es_event_setextattr_t {
    /// The file for which the extended attribute will be set
    pub target: ShouldNotBeNull<es_file_t>,
    /// The extended attribute which will be set
    pub extattr: es_string_token_t,
    _reserved: [u8; 64],
}

should_not_be_null_fields!(es_event_setextattr_t; target -> es_file_t);

/// Retrieve an extended attribute
///
/// Cache key for this event type: `(process executable file, target file)`.
#[cfg(feature = "macos_10_15_1")]
#[repr(C)]
pub struct es_event_getextattr_t {
    /// The file for which the extended attribute will be retrieved
    pub target: ShouldNotBeNull<es_file_t>,
    /// The extended attribute which will be retrieved
    pub extattr: es_string_token_t,
    _reserved: [u8; 64],
}

#[cfg(feature = "macos_10_15_1")]
should_not_be_null_fields!(es_event_getextattr_t; target -> es_file_t);

/// Delete an extended attribute
///
/// This event type does not support caching.
#[cfg(feature = "macos_10_15_1")]
#[repr(C)]
pub struct es_event_deleteextattr_t {
    /// The file for which the extended attribute will be deleted
    pub target: ShouldNotBeNull<es_file_t>,
    /// The extended attribute which will be deleted
    pub extattr: es_string_token_t,
    _reserved: [u8; 64],
}

#[cfg(feature = "macos_10_15_1")]
should_not_be_null_fields!(es_event_deleteextattr_t; target -> es_file_t);

/// Modify file mode.
///
/// The `mode` member is the desired new mode. The `target` member's `stat` information contains the
/// current mode.
///
/// Cache key for this event type: `(process executable file, target file)`.
#[repr(C)]
// 10.15.0
pub struct es_event_setmode_t {
    /// The desired new mode
    pub mode: mode_t,
    /// The file for which mode information will be modified
    pub target: ShouldNotBeNull<es_file_t>,
    _reserved: [u8; 64],
}

should_not_be_null_fields!(es_event_setmode_t; target -> es_file_t);

/// Modify file flags information.
///
/// The `flags` member is the desired set of new flags. The `target` member's `stat` information
/// contains the current set of flags.
///
/// Cache key for this event type: `(process executable file, target file)`.
#[repr(C)]
// 10.15.0
pub struct es_event_setflags_t {
    /// The desired new flags
    pub flags: u32,
    /// The file for which flags information will be modified
    pub target: ShouldNotBeNull<es_file_t>,
    _reserved: [u8; 64],
}

should_not_be_null_fields!(es_event_setflags_t; target -> es_file_t);

/// Modify file owner information
///
/// The `uid` and `gid` members are the desired new values. The `target` member's `stat`
/// information contains the current uid and gid values.
///
/// Cache key for this event type: `(process executable file, target file)`.
#[repr(C)]
// 10.15.0
pub struct es_event_setowner_t {
    /// The desired new UID
    pub uid: uid_t,
    /// The desired new GID
    pub gid: gid_t,
    /// The file for which owner information will be modified
    pub target: ShouldNotBeNull<es_file_t>,
    _reserved: [u8; 64],
}

should_not_be_null_fields!(es_event_setowner_t; target -> es_file_t);

/// Close a file descriptor
///
/// This event type does not support caching (notify-only).
#[repr(C)]
// 10.15.0
pub struct es_event_close_t {
    /// Set to `true` if the target file being closed has been modified
    ///
    /// The `modified` flag only reflects that a file was or was not modified by filesystem syscall.
    /// If a file was only modifed though a memory mapping this flag will be `false`, but
    /// `was_mapped_writable` (message version >= 6) will be true.
    pub modified: bool,
    /// The file that is being closed
    pub target: ShouldNotBeNull<es_file_t>,
    pub anon0: es_event_close_t_anon_0,
}

should_not_be_null_fields!(es_event_close_t; target -> es_file_t);

/// See [`es_event_close_t`].
#[repr(C)]
pub union es_event_close_t_anon_0 {
    _reserved: [u8; 64],
    /// Indicates that at some point in the lifetime of the target file vnode it was mapped into a
    /// process as writable.
    ///
    /// `was_mapped_writable` only indicates whether the target file was mapped into writable memory
    /// or not for the lifetime of the vnode. It does not indicate whether the file has actually
    /// been written to by way of writing to mapped memory, and it does not indicate whether the
    /// file is currently still mapped writable. Correct interpretation requires consideration of
    /// vnode lifetimes in the kernel.
    ///
    /// Field available only if message version >= 6.
    #[cfg(feature = "macos_13_0_0")]
    pub was_mapped_writable: bool,
}

/// Create a file system object.
///
/// If an object is being created but has not yet been created, the `destination_type` will be
/// `ES_DESTINATION_TYPE_NEW_PATH`.
///
/// Typically `ES_EVENT_TYPE_NOTIFY_CREATE` events are fired after the object has been created and
/// the `destination_type` will be `ES_DESTINATION_TYPE_EXISTING_FILE`. The exception to this is
/// for notifications that occur if an ES client responds to an `ES_EVENT_TYPE_AUTH_CREATE` event
/// with `ES_AUTH_RESULT_DENY`.
///
/// This event can fire multiple times for a single syscall, for example when the syscall has to be
/// retried due to racing VFS operations.
///
/// This event type does not support caching.
#[repr(C)]
// 10.15.0
pub struct es_event_create_t {
    /// Whether or not the destination refers to an existing file (see note)
    pub destination_type: es_destination_type_t,
    /// Information about the destination of the new file (see note)
    pub destination: es_event_create_t_anon_0,
    _reserved2: [u8; 16],
    pub anon_1: es_event_create_t_anon_1,
}

/// See [`es_event_create_t`]
#[repr(C)]
pub union es_event_create_t_anon_0 {
    /// The file system object that was created
    pub existing_file: ShouldNotBeNull<es_file_t>,
    pub new_path: ManuallyDrop<es_event_create_t_anon_0_anon_0>,
}

/// See [`es_event_create_t_anon_0`]
#[repr(C)]
pub struct es_event_create_t_anon_0_anon_0 {
    /// The directory in which the new file system object will be created
    pub dir: ShouldNotBeNull<es_file_t>,
    /// The name of the new file system object to create
    pub filename: es_string_token_t,
    /// Mode of the file system object to create
    pub mode: mode_t,
}

should_not_be_null_fields!(es_event_create_t_anon_0_anon_0; dir -> es_file_t);

/// See [`es_event_create_t`]
#[repr(C)]
pub union es_event_create_t_anon_1 {
    _reserved: [u8; 48],
    #[cfg(feature = "macos_10_15_1")]
    pub anon_0: ManuallyDrop<es_event_create_t_anon_1_anon_0>,
}

/// See [`es_event_create_t_anon_1`]
#[repr(C)]
#[cfg(feature = "macos_10_15_1")]
pub struct es_event_create_t_anon_1_anon_0 {
    /// The ACL that the new file system object got or gets created with.
    ///
    /// May be `NULL` if the file system object gets created without ACL.
    ///
    /// See warning about usage on [`acl_t`].
    ///
    /// Field available only if message version >= 2.
    pub acl: acl_t,
}

/// Terminate a process
///
/// This event type does not support caching (notify-only).
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
// 10.15.0
pub struct es_event_exit_t {
    /// The exit status of a process (same format as `wait(2)`)
    pub stat: c_int,
    _reserved: [u8; 64],
}

/// Exchange data atomically between two files
///
/// This event type does not support caching.
#[repr(C)]
// 10.15.0
pub struct es_event_exchangedata_t {
    /// The first file to be exchanged
    pub file1: ShouldNotBeNull<es_file_t>,
    /// The second file to be exchanged
    pub file2: ShouldNotBeNull<es_file_t>,
    _reserved: [u8; 64],
}

should_not_be_null_fields!(es_event_exchangedata_t; file1 -> es_file_t, file2 -> es_file_t);

/// Write to a file
///
/// This event type does not support caching (notify-only).
#[repr(C)]
// 10.15.0
pub struct es_event_write_t {
    /// The file being written to
    pub target: ShouldNotBeNull<es_file_t>,
    _reserved: [u8; 64],
}

should_not_be_null_fields!(es_event_write_t; target -> es_file_t);

/// Truncate to a file
///
/// This event type does not support caching.
#[repr(C)]
// 10.15.0
pub struct es_event_truncate_t {
    /// The file being truncated
    pub target: ShouldNotBeNull<es_file_t>,
    _reserved: [u8; 64],
}

should_not_be_null_fields!(es_event_truncate_t; target -> es_file_t);

/// Changes directories
///
/// Cache key for this event type: `(process executable file, target directory)`.
#[cfg(feature = "macos_10_15_1")]
#[repr(C)]
pub struct es_event_chdir_t {
    /// The desired new current working directory
    pub target: ShouldNotBeNull<es_file_t>,
    _reserved: [u8; 64],
}

#[cfg(feature = "macos_10_15_1")]
should_not_be_null_fields!(es_event_chdir_t; target -> es_file_t);

/// View stat information of a file
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_10_15_1")]
#[repr(C)]
pub struct es_event_stat_t {
    /// The file for which stat information will be retrieved
    pub target: ShouldNotBeNull<es_file_t>,
    _reserved: [u8; 64],
}

#[cfg(feature = "macos_10_15_1")]
should_not_be_null_fields!(es_event_stat_t; target -> es_file_t);

/// Changes the root directory for a process
///
/// Cache key for this event type: `(process executable file, target directory)`.
#[cfg(feature = "macos_10_15_1")]
#[repr(C)]
pub struct es_event_chroot_t {
    /// The directory which will be the new root
    pub target: ShouldNotBeNull<es_file_t>,
    _reserved: [u8; 64],
}

#[cfg(feature = "macos_10_15_1")]
should_not_be_null_fields!(es_event_chroot_t; target -> es_file_t);

/// List extended attributes of a file
///
/// Cache key for this event type: `(process executable file, target file)`.
#[cfg(feature = "macos_10_15_1")]
#[repr(C)]
pub struct es_event_listextattr_t {
    /// The file for which extended attributes information are being retrieved
    pub target: ShouldNotBeNull<es_file_t>,
    _reserved: [u8; 64],
}

#[cfg(feature = "macos_10_15_1")]
should_not_be_null_fields!(es_event_listextattr_t; target -> es_file_t);

/// Open a connection to an I/O Kit IOService.
///
/// This event is fired when a process calls `IOServiceOpen()` in order to open a communications
/// channel with an I/O Kit driver.  The event does not correspond to driver <-> device
/// communication and is neither providing visibility nor access control into devices being
/// attached.
///
/// This event type does not support caching.
#[repr(C)]
// 10.15.0
pub struct es_event_iokit_open_t {
    /// A constant specifying the type of connection to be created, interpreted only by the
    /// IOService's family. This field corresponds to the type argument to `IOServiceOpen()`.
    pub user_client_type: u32,
    /// Meta class name of the user client instance
    pub user_client_class: es_string_token_t,
    _reserved: [u8; 64],
}

ffi_wrap_enum!(
    es_get_task_type_t(u32);

    == MACOS_10_15_0;
    /// Task port obtained by calling e.g. `task_for_pid()`, where the caller obtains a task port
    /// for a process identified by pid
    ES_GET_TASK_TYPE_TASK_FOR_PID = 0,
    /// Task port obtained by calling e.g. `processor_set_tasks()`, where the caller obtains a set
    /// of task ports
    ES_GET_TASK_TYPE_EXPOSE_TASK = 1,
    --
    /// Task port obtained by calling e.g. `task_identity_token_get_task_port()`, where the caller
    /// obtains a task port for a process identified by an identity token. Task identity tokens
    /// generally have to be given up by the target process voluntarily prior to the conversion
    /// into task ports.
    ES_GET_TASK_TYPE_IDENTITY_TOKEN = 2,
);

/// Get a process's task control port.
///
/// This event is fired when a process obtains a send right to a task control port (e.g.
/// `task_for_pid()`, `task_identity_token_get_task_port()`, `processor_set_tasks()` and other
/// means).
///
/// Task control ports were formerly known as simply "task ports".
///
/// There are many legitimate reasons why a process might need to obtain a send right to a task
/// control port of another process, not limited to intending to debug or suspend the target
/// process. For instance, frameworks and their daemons may need to obtain a task control port to
/// fulfill requests made by the target process. Obtaining a task control port is in itself not
/// indicative of malicious activity. Denying system processes acquiring task control ports may
/// result in breaking system functionality in potentially fatal ways.
///
/// Cache key for this event type: `(process executable file, target executable file)`.
#[repr(C)]
// 10.15.0
pub struct es_event_get_task_t {
    /// The process for which the task control port will be retrieved
    pub target: ShouldNotBeNull<es_process_t>,
    /// Type indicating how the process is obtaining the task port for the target process.
    ///
    /// Field available only if message version >= 5.
    pub type_: es_get_task_type_t,
    _reserved: [u8; 60],
}

should_not_be_null_fields!(es_event_get_task_t; target -> es_process_t);

/// Get a process's task read port.
///
/// This event is fired when a process obtains a send right to a task read port (e.g.
/// `task_read_for_pid()`, `task_identity_token_get_task_port()`).
///
/// Cache key for this event type: `(process executable file, target executable file)`.
#[cfg(feature = "macos_11_3_0")]
#[repr(C)]
pub struct es_event_get_task_read_t {
    /// The process for which the task read port will be retrieved
    pub target: ShouldNotBeNull<es_process_t>,
    /// Type indicating how the process is obtaining the task port for the target process.
    ///
    /// Field available only if message version >= 5.
    pub type_: es_get_task_type_t,
    _reserved: [u8; 60],
}

#[cfg(feature = "macos_11_3_0")]
should_not_be_null_fields!(es_event_get_task_read_t; target -> es_process_t);

/// Get a process's task inspect port.
///
/// This event is fired when a process obtains a send right to a task inspect port (e.g.
/// `task_inspect_for_pid()`, `task_identity_token_get_task_port()`).
///
/// This event type does not support caching.
#[cfg(feature = "macos_11_3_0")]
#[repr(C)]
pub struct es_event_get_task_inspect_t {
    /// The process for which the task inspect port will be retrieved
    pub target: ShouldNotBeNull<es_process_t>,
    /// Type indicating how the process is obtaining the task port for the target process.
    ///
    /// Field available only if message version >= 5.
    pub type_: es_get_task_type_t,
    _reserved: [u8; 60],
}

#[cfg(feature = "macos_11_3_0")]
should_not_be_null_fields!(es_event_get_task_inspect_t; target -> es_process_t);

/// Get a process's task name port.
///
/// This event is fired when a process obtains a send right to a task name port (e.g.
/// `task_name_for_pid()`, `task_identity_token_get_task_port()`).
///
/// This event type does not support caching.
#[cfg(feature = "macos_11_0_0")]
#[repr(C)]
pub struct es_event_get_task_name_t {
    /// The process for which the task name port will be retrieved
    pub target: ShouldNotBeNull<es_process_t>,
    /// Type indicating how the process is obtaining the task port for the target process.
    ///
    /// Field available only if message version >= 5.
    pub type_: es_get_task_type_t,
    _reserved: [u8; 60],
}

#[cfg(feature = "macos_11_0_0")]
should_not_be_null_fields!(es_event_get_task_name_t; target -> es_process_t);

/// Retrieve file system attributes
///
/// Cache key for this event type: `(process executable file, target file)`.
#[cfg(feature = "macos_10_15_1")]
#[repr(C)]
pub struct es_event_getattrlist_t {
    /// The attributes that will be retrieved
    pub attrlist: attrlist,
    /// The file for which attributes will be retrieved
    pub target: ShouldNotBeNull<es_file_t>,
    _reserved: [u8; 64],
}

#[cfg(feature = "macos_10_15_1")]
should_not_be_null_fields!(es_event_getattrlist_t; target -> es_file_t);

/// Modify file system attributes
///
/// This event type does not support caching.
#[repr(C)]
// 10.15.0
pub struct es_event_setattrlist_t {
    /// The attributes that will be modified
    pub attrlist: attrlist,
    /// The file for which attributes will be modified
    pub target: ShouldNotBeNull<es_file_t>,
    _reserved: [u8; 64],
}

should_not_be_null_fields!(es_event_setattrlist_t; target -> es_file_t);

/// Update file contents via the `FileProvider` framework
///
/// This event type does not support caching.
#[repr(C)]
// 10.15.0
pub struct es_event_file_provider_update_t {
    /// The staged file that has had its contents updated
    pub source: ShouldNotBeNull<es_file_t>,
    /// The destination that the staged `source` file will be moved to
    pub target_path: es_string_token_t,
    _reserved: [u8; 64],
}

should_not_be_null_fields!(es_event_file_provider_update_t; source -> es_file_t);

/// Materialize a file via the `FileProvider` framework
///
/// This event type does not support caching.
#[repr(C)]
// 10.15.0
pub struct es_event_file_provider_materialize_t {
    pub instigator: ShouldNotBeNull<es_process_t>,
    /// The staged file that has been materialized
    pub source: ShouldNotBeNull<es_file_t>,
    /// The destination of the staged `source` file
    pub target: ShouldNotBeNull<es_file_t>,
    _reserved: [u8; 64],
}

should_not_be_null_fields!(
    es_event_file_provider_materialize_t;
    instigator -> es_process_t,
    source -> es_file_t,
    target -> es_file_t
);

/// Resolve a symbolic link.
///
/// This is not limited only to `readlink(2)`. Other operations such as path lookups can also cause
/// this event to be fired.
///
/// *Caching support is undocumented for this event.*
#[repr(C)]
// 10.15.0
pub struct es_event_readlink_t {
    /// The symbolic link that is attempting to be resolved
    pub source: ShouldNotBeNull<es_file_t>,
    _reserved: [u8; 64],
}

should_not_be_null_fields!(es_event_readlink_t; source -> es_file_t);

/// Lookup a file system object.
///
/// The `relative_target` data may contain untrusted user input.
///
/// This event type does not support caching (notify-only).
#[repr(C)]
// 10.15.0
pub struct es_event_lookup_t {
    /// The current directory
    pub source_dir: ShouldNotBeNull<es_file_t>,
    /// The path to lookup relative to the `source_dir`
    pub relative_target: es_string_token_t,
    _reserved: [u8; 64],
}

should_not_be_null_fields!(es_event_lookup_t; source_dir -> es_file_t);

/// Test file access
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_10_15_1")]
#[repr(C)]
pub struct es_event_access_t {
    /// Access permission to check
    pub mode: i32,
    /// The file to check for access
    pub target: ShouldNotBeNull<es_file_t>,
    _reserved: [u8; 64],
}

#[cfg(feature = "macos_10_15_1")]
should_not_be_null_fields!(es_event_access_t; target -> es_file_t);

/// Change file access and modification times (e.g. via `utimes(2)`)
///
/// Cache key for this event type: `(process executable file, target file)`.
#[cfg(feature = "macos_10_15_1")]
#[repr(C)]
pub struct es_event_utimes_t {
    /// The path which will have its times modified
    pub target: ShouldNotBeNull<es_file_t>,
    /// The desired new access time
    pub atime: timespec,
    /// The desired new modification time
    pub mtime: timespec,
    _reserved: [u8; 64],
}

#[cfg(feature = "macos_10_15_1")]
should_not_be_null_fields!(es_event_utimes_t; target -> es_file_t);

/// Clone a file
///
/// This event type does not support caching.
#[cfg(feature = "macos_10_15_1")]
#[repr(C)]
pub struct es_event_clone_t {
    /// The file that will be cloned
    pub source: ShouldNotBeNull<es_file_t>,
    /// The directory into which the `source` file will be cloned
    pub target_dir: ShouldNotBeNull<es_file_t>,
    /// The name of the new file to which `source` will be cloned
    pub target_name: es_string_token_t,
    _reserved: [u8; 64],
}

#[cfg(feature = "macos_10_15_1")]
should_not_be_null_fields!(es_event_clone_t; source -> es_file_t, target_dir -> es_file_t);

/// Copy a file using the copyfile syscall.
///
/// Not to be confused with `copyfile(3)`.
///
/// Prior to macOS 12.0, the `copyfile` syscall fired `open`, `unlink` and `auth` create events, but
/// no notify `create`, nor `write` or `close` events.
///
/// This event type does not support caching.
#[cfg(feature = "macos_12_0_0")]
#[repr(C)]
pub struct es_event_copyfile_t {
    /// The file that will be cloned
    pub source: ShouldNotBeNull<es_file_t>,
    /// The file existing at the target path that will be overwritten by the copyfile operation.
    /// `NULL` if no such file exists.
    pub target_file: *mut es_file_t,
    /// The directory into which the `source` file will be copied
    pub target_dir: ShouldNotBeNull<es_file_t>,
    /// The name of the new file to which `source` will be copied
    pub target_name: es_string_token_t,
    /// Corresponds to mode argument of the copyfile syscall
    pub mode: mode_t,
    /// Corresponds to flags argument of the copyfile syscall
    pub flags: i32,
    _reserved: [u8; 56],
}

#[cfg(feature = "macos_12_0_0")]
should_not_be_null_fields!(es_event_copyfile_t; source -> es_file_t, target_dir -> es_file_t);
#[cfg(feature = "macos_12_0_0")]
null_fields!(es_event_copyfile_t; target_file -> es_file_t);

/// File control
///
/// This event type does not support caching.
#[cfg(feature = "macos_10_15_1")]
#[repr(C)]
pub struct es_event_fcntl_t {
    /// The target file on which the file control command will be performed
    pub target: ShouldNotBeNull<es_file_t>,
    /// The `cmd` argument given to `fcntl(2)`
    pub cmd: i32,
    _reserved: [u8; 64],
}

#[cfg(feature = "macos_10_15_1")]
should_not_be_null_fields!(es_event_fcntl_t; target -> es_file_t);

/// Read directory entries
///
/// Cache key for this event type: `(process executable file, target directory)`.
#[cfg(feature = "macos_10_15_1")]
#[repr(C)]
pub struct es_event_readdir_t {
    /// The directory whose contents will be read
    pub target: ShouldNotBeNull<es_file_t>,
    _reserved: [u8; 64],
}

#[cfg(feature = "macos_10_15_1")]
should_not_be_null_fields!(es_event_readdir_t; target -> es_file_t);

/// Retrieve file system path based on FSID.
///
/// This event can fire multiple times for a single syscall, for example when the syscall has to be
/// retried due to racing VFS operations.
///
/// Cache key for this event type: `(process executable file, target file)`.
#[cfg(feature = "macos_10_15_1")]
#[repr(C)]
pub struct es_event_fsgetpath_t {
    /// Describes the file system path that will be retrieved
    pub target: ShouldNotBeNull<es_file_t>,
    _reserved: [u8; 64],
}

#[cfg(feature = "macos_10_15_1")]
should_not_be_null_fields!(es_event_fsgetpath_t; target -> es_file_t);

/// Modify the system time
///
/// This event is not fired if the program contains the entitlement `com.apple.private.settime`.
/// Additionally, even if an ES client responds to `ES_EVENT_TYPE_AUTH_SETTIME` events with
/// `ES_AUTH_RESULT_ALLOW`, the operation may still fail for other reasons (e.g. unprivileged user).
///
/// This event type does not support caching.
#[cfg(feature = "macos_10_15_1")]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct es_event_settime_t {
    _reserved: [u8; 64],
}

/// Duplicate a file descriptor
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_10_15_1")]
#[repr(C)]
pub struct es_event_dup_t {
    /// Describes the file the duplicated file descriptor points to
    pub target: ShouldNotBeNull<es_file_t>,
    _reserved: [u8; 64],
}

#[cfg(feature = "macos_10_15_1")]
should_not_be_null_fields!(es_event_dup_t; target -> es_file_t);

/// Fired when a UNIX-domain socket is about to be bound to a path
///
/// This event type does not support caching.
#[cfg(feature = "macos_10_15_1")]
#[repr(C)]
pub struct es_event_uipc_bind_t {
    /// Describes the directory the socket file is created in
    pub dir: ShouldNotBeNull<es_file_t>,
    /// The filename of the socket file
    pub filename: es_string_token_t,
    /// The mode of the socket file
    pub mode: mode_t,
    _reserved: [u8; 64],
}

#[cfg(feature = "macos_10_15_1")]
should_not_be_null_fields!(es_event_uipc_bind_t; dir -> es_file_t);

/// Fired when a UNIX-domain socket is about to be connected.
///
/// Cache key for this event type: `(process executable file, socket file)`.
#[cfg(feature = "macos_10_15_1")]
#[repr(C)]
pub struct es_event_uipc_connect_t {
    /// Describes the socket file that the socket is bound to
    pub file: ShouldNotBeNull<es_file_t>,
    /// The cmmunications domain of the socket (see `socket(2)`)
    pub domain: c_int,
    /// The type of the socket (see `socket(2)`)
    pub type_: c_int,
    /// The protocol of the socket (see `socket(2)`)
    pub protocol: c_int,
    _reserved: [u8; 64],
}

#[cfg(feature = "macos_10_15_1")]
should_not_be_null_fields!(es_event_uipc_connect_t; file -> es_file_t);

/// Set a file ACL.
///
/// This event type does not support caching.
#[cfg(feature = "macos_10_15_1")]
#[repr(C)]
pub struct es_event_setacl_t {
    /// Describes the file whose ACL is being set.
    pub target: ShouldNotBeNull<es_file_t>,
    /// Describes whether or not the ACL on the `target` is being set or cleared
    pub set_or_clear: es_set_or_clear_t,
    /// Union that is valid when `set_or_clear` is set to `ES_SET`
    pub acl: es_event_setacl_t_anon_0,
    _reserved: [u8; 64],
}

#[cfg(feature = "macos_10_15_1")]
should_not_be_null_fields!(es_event_setacl_t; target -> es_file_t);

#[cfg(feature = "macos_10_15_1")]
impl es_event_setacl_t {
    /// `Some` if `set_or_clear` is `ES_SET`
    ///
    /// # Safety
    ///
    /// `acl_t` is a pointer to the opaque ACL, be careful not to extend it's lifetime past that
    /// of `self`. The `acl` and `set_or_clear` fields must be synced.
    pub unsafe fn acl(&self) -> Option<&acl_t> {
        if self.set_or_clear == es_set_or_clear_t::ES_SET {
            // Safety: we checked `set_or_clear` for the correct value just before and the field
            // are guaranteed to be in sync by the caller.
            Some(unsafe { &self.acl.set })
        } else {
            None
        }
    }
}

/// See [`es_event_setacl_t`]
#[cfg(feature = "macos_10_15_1")]
#[repr(C)]
pub union es_event_setacl_t_anon_0 {
    /// The [`acl_t`] structure to be used by various `acl(3)` functions.
    ///
    /// See the warning on the type to learn how to use it safely.
    ///
    /// This is theoretically `ShouldNotBeNull` but since it can be absent depending on
    /// [`es_event_setacl_t::set_or_clear`], this is not represented in the type here
    pub set: acl_t,
}

/// Fired when a pseudoterminal control device is granted
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_10_15_4")]
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct es_event_pty_grant_t {
    /// Major and minor numbers of device
    pub dev: dev_t,
    _reserved: [u8; 64],
}

/// Fired when a pseudoterminal control device is closed
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_10_15_4")]
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct es_event_pty_close_t {
    /// Major and minor numbers of device
    pub dev: dev_t,
    _reserved: [u8; 64],
}

/// Access control check for retrieving process information
///
/// Cache key for this event type: `(process executable file, target process executable file, type)`.
#[cfg(feature = "macos_10_15_4")]
#[repr(C)]
pub struct es_event_proc_check_t {
    /// The process for which the access will be checked
    pub target: *mut es_process_t,
    /// The type of call number used to check the access on the target process
    pub type_: es_proc_check_type_t,
    /// The flavor used to check the access on the target process
    pub flavor: c_int,
    _reserved: [u8; 64],
}

#[cfg(feature = "macos_10_15_4")]
null_fields!(es_event_proc_check_t; target -> es_process_t);

/// Access control check for searching a volume or a mounted file system
///
/// Cache key for this event type: `(process executable file, target file)`.
#[cfg(feature = "macos_11_0_0")]
#[repr(C)]
pub struct es_event_searchfs_t {
    /// The attributes that will be used to do the search
    pub attrlist: attrlist,
    /// The volume whose contents will be searched
    pub target: ShouldNotBeNull<es_file_t>,
    _reserved: [u8; 64],
}

#[cfg(feature = "macos_11_0_0")]
should_not_be_null_fields!(es_event_searchfs_t; target -> es_file_t);

ffi_wrap_enum!(
    /// This enum describes the type of suspend/resume operations that are currently used
    es_proc_suspend_resume_type_t(u32);

    == MACOS_10_15_0;
    ES_PROC_SUSPEND_RESUME_TYPE_SUSPEND = 0,
    ES_PROC_SUSPEND_RESUME_TYPE_RESUME = 1,
    --
    ES_PROC_SUSPEND_RESUME_TYPE_SHUTDOWN_SOCKETS = 3,
);

/// Fired when one of pid_suspend, pid_resume or pid_shutdown_sockets is called on a process
///
/// This event type does not support caching.
#[cfg(feature = "macos_11_0_0")]
#[repr(C)]
pub struct es_event_proc_suspend_resume_t {
    /// The process that is being suspended, resumed, or is the object of a pid_shutdown_sockets call
    pub target: *mut es_process_t,
    /// The type of operation that was called on the target process
    pub type_: es_proc_suspend_resume_type_t,
    _reserved: [u8; 64],
}

#[cfg(feature = "macos_11_0_0")]
null_fields!(es_event_proc_suspend_resume_t; target -> es_process_t);

/// Code signing status for process was invalidated.
///
/// This event fires when the `CS_VALID` bit is removed from a process' CS flags, that is, when the
/// first invalid page is paged in for a process with an otherwise valid code signature, or when a
/// process is explicitly invalidated by a `csops(CS_OPS_MARKINVALID)` syscall. This event does not
/// fire if `CS_HARD` was set, since `CS_HARD` by design prevents the process from going invalid.
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_11_0_0")]
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct es_event_cs_invalidated_t {
    _reserved: [u8; 64],
}

/// Fired when one process attempts to attach to another process
///
/// This event can fire multiple times for a single trace attempt, for example when the processes to
/// which is being attached is reparented during the operation
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_11_0_0")]
#[repr(C)]
pub struct es_event_trace_t {
    /// The process that will be attached to by the process that instigated the event
    pub target: ShouldNotBeNull<es_process_t>,
    _reserved: [u8; 64],
}

#[cfg(feature = "macos_11_0_0")]
should_not_be_null_fields!(es_event_trace_t; target -> es_process_t);

/// Notification that a process has attempted to create a thread in another process by calling one
/// of the `thread_create` or `thread_create_running` MIG routines
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_11_0_0")]
#[repr(C)]
pub struct es_event_remote_thread_create_t {
    /// The process in which a new thread was created
    pub target: ShouldNotBeNull<es_process_t>,
    /// The new thread state in case of `thread_create_running`, `NULL` in case of `thread_create`
    pub thread_state: *mut es_thread_state_t,
    _reserved: [u8; 64],
}

#[cfg(feature = "macos_11_0_0")]
should_not_be_null_fields!(es_event_remote_thread_create_t; target -> es_process_t);
#[cfg(feature = "macos_11_0_0")]
null_fields!(es_event_remote_thread_create_t; thread_state -> es_thread_state_t);

/// Notification that a process has called `setuid()`
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_12_0_0")]
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct es_event_setuid_t {
    /// The `uid` argument to the `setuid()` syscall
    pub uid: uid_t,
    _reserved: [u8; 64],
}

/// Notification that a process has called `setgid()`
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_12_0_0")]
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct es_event_setgid_t {
    /// The `gid` argument to the `setgid()` syscall
    pub gid: uid_t,
    _reserved: [u8; 64],
}

/// Notification that a process has called `seteuid()`
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_12_0_0")]
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct es_event_seteuid_t {
    /// The `euid` argument to the `seteuid()` syscall
    pub euid: uid_t,
    _reserved: [u8; 64],
}

/// Notification that a process has called `setegid()`
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_12_0_0")]
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct es_event_setegid_t {
    /// The `egid` argument to the `setegid()` syscall
    pub egid: uid_t,
    _reserved: [u8; 64],
}

/// Notification that a process has called `setreuid()`
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_12_0_0")]
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct es_event_setreuid_t {
    /// The `ruid` argument to the `setreuid()` syscall
    pub ruid: uid_t,
    /// The `euid` argument to the `setreuid()` syscall
    pub euid: uid_t,
    _reserved: [u8; 64],
}

/// Notification that a process has called `setregid()`
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_12_0_0")]
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct es_event_setregid_t {
    /// The `rgid` argument to the `setregid()` syscall
    pub rgid: uid_t,
    /// The `egid` argument to the `setregid()` syscall
    pub egid: uid_t,
    _reserved: [u8; 64],
}

/// OpenDirectory authentication data for type
/// [`ES_AUTHENTICATION_TYPE_OD`][crate::es_authentication_type_t].
#[cfg(feature = "macos_13_0_0")]
#[repr(C)]
pub struct es_event_authentication_od_t {
    /// Process that instigated the authentication (XPC caller that asked for authentication).
    pub instigator: ShouldNotBeNull<es_process_t>,
    /// OD record type against which OD is authenticating. Typically `Users`, but other record types
    /// can auth too.
    pub record_type: es_string_token_t,
    /// OD record name against which OD is authenticating. For record type `Users`, this is the
    /// username.
    pub record_name: es_string_token_t,
    /// OD node against which OD is authenticating. Typically one of `/Local/Default`, `/LDAPv3/
    /// <server>` or `/Active Directory/<domain>`.
    pub node_name: es_string_token_t,
    /// Optional. If node_name is "/Local/Default", this is the path of the database against which
    /// OD is authenticating.
    pub db_path: es_string_token_t,
}

#[cfg(feature = "macos_13_0_0")]
should_not_be_null_fields!(es_event_authentication_od_t; instigator -> es_process_t);

#[cfg(feature = "macos_13_0_0")]
ffi_wrap_enum!(
    /// See [`es_event_authentication_touchid_t`]
    es_touchid_mode_t(u32);

    == MACOS_13_0_0;
    ES_TOUCHID_MODE_VERIFICATION = 0,
    --
    ES_TOUCHID_MODE_IDENTIFICATION = 1,
);

/// TouchID authentication data for type
/// [`ES_AUTHENTICATION_TYPE_TOUCHID`][crate::es_authentication_type_t].
#[cfg(feature = "macos_13_0_0")]
#[repr(C)]
pub struct es_event_authentication_touchid_t {
    /// Process that instigated the authentication (XPC caller that asked for authentication).
    pub instigator: ShouldNotBeNull<es_process_t>,
    /// TouchID authentication type
    pub touchid_mode: es_touchid_mode_t,
    /// Describes whether or not the uid of the user authenticated is available
    pub has_uid: bool,
    /// Union that is valid when `has_uid` is set to `true`
    pub anon0: es_event_authentication_touchid_t_anon0,
}

#[cfg(feature = "macos_13_0_0")]
should_not_be_null_fields!(es_event_authentication_touchid_t; instigator -> es_process_t);

/// See [`es_event_authentication_touchid_t`]
#[cfg(feature = "macos_13_0_0")]
#[repr(C)]
pub union es_event_authentication_touchid_t_anon0 {
    /// Uid of user that was authenticated. This will be set when `success` is true and
    /// `touchid_mode` is of verification type i.e.
    /// [`ES_TOUCHID_MODE_VERIFICATION`][crate::es_authentication_type_t].
    pub uid: uid_t,
}

/// Token authentication data for type
/// [`ES_AUTHENTICATION_TYPE_TOKEN`][crate::es_authentication_type_t].
#[cfg(feature = "macos_13_0_0")]
#[repr(C)]
pub struct es_event_authentication_token_t {
    /// Process that instigated the authentication (XPC caller that asked for authentication).
    pub instigator: ShouldNotBeNull<es_process_t>,
    /// Hash of the public key which CryptoTokenKit is authenticating.
    pub pubkey_hash: es_string_token_t,
    /// Token identifier of the event which CryptoTokenKit is authenticating.
    pub token_id: es_string_token_t,
    /// Optional. This will be available if token is used for GSS PKINIT authentication for
    /// obtaining a kerberos TGT. `NULL` in all other cases.
    pub kerberos_principal: es_string_token_t,
}

#[cfg(feature = "macos_13_0_0")]
should_not_be_null_fields!(es_event_authentication_token_t; instigator -> es_process_t);

#[cfg(feature = "macos_13_0_0")]
ffi_wrap_enum!(
    /// See [`es_event_authentication_auto_unlock_t`].
    es_auto_unlock_type_t(u32);

    == MACOS_13_0_0;
    /// Unlock the machine using Apple Watch.
    ES_AUTO_UNLOCK_MACHINE_UNLOCK = 1,
    --
    /// Approve an authorization prompt using Apple Watch.
    ES_AUTO_UNLOCK_AUTH_PROMPT = 2,
);

/// Auto Unlock authentication data for type
/// [`ES_AUTHENTICATION_TYPE_TOKEN`][crate::es_authentication_type_t].
///
/// This kind of authentication is performed when authenticating to the local Mac using an Apple
/// Watch for the purpose of unlocking the machine or confirming an authorization prompt. Auto
/// Unlock is part of Continuity.
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_13_0_0")]
#[repr(C)]
pub struct es_event_authentication_auto_unlock_t {
    /// Username for which the authentication was attempted.
    pub username: es_string_token_t,
    /// Purpose of the authentication.
    pub type_: es_auto_unlock_type_t,
}

/// Notification that an authentication was performed.
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_13_0_0")]
#[repr(C)]
pub struct es_event_authentication_t {
    /// True iff authentication was successful.
    pub success: bool,
    /// The type of authentication.
    pub type_: es_authentication_type_t,
    /// Type-specific data describing the authentication.
    pub data: es_event_authentication_t_anon0,
}

/// See [`es_event_authentication_t`]
#[cfg(feature = "macos_13_0_0")]
#[repr(C)]
#[derive(Copy, Clone)]
pub union es_event_authentication_t_anon0 {
    pub od: ShouldNotBeNull<es_event_authentication_od_t>,
    pub touchid: ShouldNotBeNull<es_event_authentication_touchid_t>,
    pub token: ShouldNotBeNull<es_event_authentication_token_t>,
    pub auto_unlock: ShouldNotBeNull<es_event_authentication_auto_unlock_t>,
}

#[cfg(feature = "macos_13_0_0")]
should_not_be_null_fields!(
    es_event_authentication_t_anon0;
    od -> es_event_authentication_od_t,
    touchid -> es_event_authentication_touchid_t,
    token -> es_event_authentication_token_t,
    auto_unlock -> es_event_authentication_auto_unlock_t,
);

/// Notification that XProtect detected malware.
///
/// For any given malware incident, XProtect may emit zero or more `xp_malware_detected` events, and
/// zero or more `xp_malware_remediated` events.
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_13_0_0")]
#[repr(C)]
pub struct es_event_xp_malware_detected_t {
    /// Version of the signatures used for detection. Currently corresponds to XProtect version.
    pub signature_version: es_string_token_t,
    /// String identifying the malware that was detected.
    pub malware_identifier: es_string_token_t,
    /// String identifying the incident, intended for linking multiple malware detected and
    /// remediated events.
    pub incident_identifier: es_string_token_t,
    /// Path where malware was detected. This path is not necessarily a malicious binary, it can
    /// also be a legitimate file containing a malicious portion.
    pub detected_path: es_string_token_t,
}

/// Notification that XProtect remediated malware.
///
/// For any given malware incident, XProtect may emit zero or more `xp_malware_detected` events, and
/// zero or more `xp_malware_remediated` events.
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_13_0_0")]
#[repr(C)]
pub struct es_event_xp_malware_remediated_t {
    /// Version of the signatures used for remediation. Currently corresponds to XProtect version.
    pub signature_version: es_string_token_t,
    /// String identifying the malware that was detected.
    pub malware_identifier: es_string_token_t,
    /// String identifying the incident, intended for linking multiple malware detected and
    /// remediated events.
    pub incident_identifier: es_string_token_t,
    /// String indicating the type of action that was taken, e.g. "path_delete".
    pub action_type: es_string_token_t,
    /// True only if remediation was successful.
    pub success: bool,
    /// String describing specific reasons for failure or success.
    pub result_description: es_string_token_t,
    /// Optional. Path that was subject to remediation, if any. This path is not necessarily
    /// a malicious binary, it can also be a legitimate file containing a malicious portion.
    /// Specifically, the file at this path may still exist after successful remediation.
    pub remediated_path: es_string_token_t,
    /// Audit token of process that was subject to remediation, if any.
    pub remediated_process_audit_token: *mut audit_token_t,
}

#[cfg(feature = "macos_13_0_0")]
null_fields!(es_event_xp_malware_remediated_t; remediated_process_audit_token -> audit_token_t);

/// A session identifier identifying a on-console or off-console graphical session.
///
/// A graphical session exists and can potentially be attached to via Screen Sharing before a user
/// is logged in. EndpointSecurity clients should treat the `graphical_session_id` as an opaque
/// identifier and not assign special meaning to it beyond correlating events pertaining to the same
/// graphical session. Not to be confused with the audit session ID.
#[cfg(feature = "macos_13_0_0")]
pub type es_graphical_session_id_t = u32;

/// Notification that LoginWindow has logged in a user.
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_13_0_0")]
#[repr(C)]
pub struct es_event_lw_session_login_t {
    /// Short username of the user.
    pub username: es_string_token_t,
    /// Graphical session id of the session.
    pub graphical_session_id: es_graphical_session_id_t,
}

/// Notification that LoginWindow has logged out a user.
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_13_0_0")]
#[repr(C)]
pub struct es_event_lw_session_logout_t {
    /// Short username of the user.
    pub username: es_string_token_t,
    /// Graphical session id of the session.
    pub graphical_session_id: es_graphical_session_id_t,
}

/// Notification that LoginWindow locked the screen of a session.
///
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_13_0_0")]
#[repr(C)]
pub struct es_event_lw_session_lock_t {
    /// Short username of the user.
    pub username: es_string_token_t,
    /// Graphical session id of the session.
    pub graphical_session_id: es_graphical_session_id_t,
}

/// Notification that LoginWindow unlocked the screen of a session.
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_13_0_0")]
#[repr(C)]
pub struct es_event_lw_session_unlock_t {
    /// Short username of the user.
    pub username: es_string_token_t,
    /// Graphical session id of the session.
    pub graphical_session_id: es_graphical_session_id_t,
}

/// Notification that Screen Sharing has attached to a graphical session.
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_13_0_0")]
#[repr(C)]
pub struct es_event_screensharing_attach_t {
    /// True iff Screen Sharing successfully attached.
    pub success: bool,
    /// Type of source address.
    pub source_address_type: es_address_type_t,
    /// Optional. Source address of connection, or `NULL`. Depending on the transport used, the
    /// source address may or may not be available.
    pub source_address: es_string_token_t,
    /// Optional. For screen sharing initiated using an Apple ID (e.g., from Messages or FaceTime),
    /// this is the viewer's (client's) Apple ID. It is not necessarily the Apple ID that invited
    /// the screen sharing. `NULL` if unavailable.
    pub viewer_appleid: es_string_token_t,
    /// Type of authentication.
    pub authentication_type: es_string_token_t,
    /// Optional. Username used for authentication to Screen Sharing. `NULL` if authentication type
    /// doesn't use an username (e.g. simple VNC password).
    pub authentication_username: es_string_token_t,
    /// Optional. Username of the loginwindow session if available, `NULL` otherwise.
    pub session_username: es_string_token_t,
    /// True iff there was an existing user session.
    pub existing_session: bool,
    /// Graphical session id of the screen shared.
    pub graphical_session_id: es_graphical_session_id_t,
}

/// Notification that Screen Sharing has detached from a graphical session.
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_13_0_0")]
#[repr(C)]
pub struct es_event_screensharing_detach_t {
    /// Type of source address.
    pub source_address_type: es_address_type_t,
    /// Optional. Source address of connection, or `NULL`. Depending on the transport used, the
    /// source address may or may not be available.
    pub source_address: es_string_token_t,
    /// Optional. For screen sharing initiated using an Apple ID (e.g., from Messages or FaceTime),
    /// this is the viewer's (client's) Apple ID. It is not necessarily the Apple ID that invited
    /// the screen sharing. `NULL` if unavailable.
    pub viewer_appleid: es_string_token_t,
    /// Graphical session id of the screen shared.
    pub graphical_session_id: es_graphical_session_id_t,
}

#[cfg(feature = "macos_13_0_0")]
ffi_wrap_enum!(
    /// See [`es_event_openssh_login_t`]
    es_openssh_login_result_type_t(u32);

    == MACOS_13_0_0;
    ES_OPENSSH_LOGIN_EXCEED_MAXTRIES = 0,
    ES_OPENSSH_LOGIN_ROOT_DENIED = 1,
    ES_OPENSSH_AUTH_SUCCESS = 2,
    ES_OPENSSH_AUTH_FAIL_NONE = 3,
    ES_OPENSSH_AUTH_FAIL_PASSWD = 4,
    ES_OPENSSH_AUTH_FAIL_KBDINT = 5,
    ES_OPENSSH_AUTH_FAIL_PUBKEY = 6,
    ES_OPENSSH_AUTH_FAIL_HOSTBASED = 7,
    ES_OPENSSH_AUTH_FAIL_GSSAPI = 8,
    --
    ES_OPENSSH_INVALID_USER = 9,
);

/// Notification for OpenSSH login event.
///
/// This is a connection-level event. An SSH connection that is used for multiple interactive
/// sessions and/or non-interactive commands will emit only a single successful login event.
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_13_0_0")]
#[repr(C)]
pub struct es_event_openssh_login_t {
    /// True iff login was successful.
    pub success: bool,
    /// Result type for the login attempt.
    pub result_type: es_openssh_login_result_type_t,
    /// Type of source address.
    pub source_address_type: es_address_type_t,
    /// Source address of connection.
    pub source_address: es_string_token_t,
    /// Username used for login.
    pub username: es_string_token_t,
    /// Describes whether or not the uid of the user logged in is available
    pub has_uid: bool,
    /// Uid of user that was logged in.
    pub anon0: es_event_openssh_login_t_anon0,
}

/// See [`es_event_openssh_login_t`]
#[cfg(feature = "macos_13_0_0")]
#[repr(C)]
pub union es_event_openssh_login_t_anon0 {
    /// Uid of user that was logged in.
    pub uid: uid_t,
}

/// Notification for OpenSSH logout event.
///
/// This is a connection-level event. An SSH connection that is used for multiple interactive
/// sessions and/or non-interactive commands will emit only a single logout event.
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_13_0_0")]
#[repr(C)]
pub struct es_event_openssh_logout_t {
    /// Type of address used in the connection.
    pub source_address_type: es_address_type_t,
    /// Source address of the connection.
    pub source_address: es_string_token_t,
    /// Username which got logged out.
    pub username: es_string_token_t,
    /// uid of user that was logged out.
    pub uid: uid_t,
}

/// Notification for authenticated login event from `/usr/bin/login`.
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_13_0_0")]
#[repr(C)]
pub struct es_event_login_login_t {
    /// True iff login was successful.
    pub success: bool,
    /// Optional. Failure message generated.
    pub failure_message: es_string_token_t,
    /// Username used for login.
    pub username: es_string_token_t,
    /// Describes whether or not the uid of the user logged in is available or not.
    pub has_uid: bool,
    /// Union that is valid when `has_uid` is set to `true`
    pub anon0: es_event_login_login_t_anon0,
}

/// See [`es_event_login_login_t`]
#[cfg(feature = "macos_13_0_0")]
#[repr(C)]
pub union es_event_login_login_t_anon0 {
    /// Uid of user that was logged in.
    pub uid: uid_t,
}

/// Notification for authenticated logout event from `/usr/bin/login`.
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_13_0_0")]
#[repr(C)]
pub struct es_event_login_logout_t {
    /// Username used for login.
    pub username: es_string_token_t,
    /// uid of user that was logged in.
    pub uid: uid_t,
}

/// Notification for launch item being made known to background task management. This includes
/// launch agents and daemons as well as login items added by the user, via MDM or by an app.
///
/// May be emitted for items where an add was already seen previously, with or without the item
/// having changed.
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_13_0_0")]
#[repr(C)]
pub struct es_event_btm_launch_item_add_t {
    /// Optional. Process that instigated the BTM operation (XPC caller that asked for the item to
    /// be added).
    pub instigator: *mut es_process_t,
    /// Optional. App process that registered the item.
    pub app: *mut es_process_t,
    /// BTM launch item.
    pub item: ShouldNotBeNull<es_btm_launch_item_t>,
    /// Optional. If available and applicable, the POSIX executable path from the launchd plist. If
    /// the path is relative, it is relative to `item.app_url`.
    pub executable_path: es_string_token_t,
}

#[cfg(feature = "macos_13_0_0")]
should_not_be_null_fields!(es_event_btm_launch_item_add_t; item -> es_btm_launch_item_t);
#[cfg(feature = "macos_13_0_0")]
null_fields!(es_event_btm_launch_item_add_t; instigator -> es_process_t, app -> es_process_t);

/// Notification for launch item being removed from background
///        task management.  This includes launch agents and daemons as
///        well as login items added by the user, via MDM or by an app.
///
/// This event type does not support caching (notify-only).
#[cfg(feature = "macos_13_0_0")]
#[repr(C)]
pub struct es_event_btm_launch_item_remove_t {
    /// Optional. Process that instigated the BTM operation (XPC caller that asked for the item to
    /// be added).
    pub instigator: *mut es_process_t,
    /// Optional. App process that registered the item.
    pub app: *mut es_process_t,
    /// BTM launch item.
    pub item: ShouldNotBeNull<es_btm_launch_item_t>,
}

#[cfg(feature = "macos_13_0_0")]
should_not_be_null_fields!(es_event_btm_launch_item_remove_t; item -> es_btm_launch_item_t);
#[cfg(feature = "macos_13_0_0")]
null_fields!(es_event_btm_launch_item_remove_t; instigator -> es_process_t, app -> es_process_t);

/// Union of all possible events that can appear in an [`es_message_t`]
#[repr(C)]
pub union es_events_t {
    // Events added before macOS 13.0.0 use structs directly.
    //
    // Originally this union is sorted according to the members' names. Here we first sort it by
    // version to make it easy to track what was first added when. Note that events can be added
    // as AUTH in a version and NOTIFY in another. The first appeareance is the one used for the
    // sorting here.

    // 10.15.0
    pub close: ManuallyDrop<es_event_close_t>,
    pub create: ManuallyDrop<es_event_create_t>,
    pub exchangedata: ManuallyDrop<es_event_exchangedata_t>,
    pub exec: ManuallyDrop<es_event_exec_t>,
    pub exit: ManuallyDrop<es_event_exit_t>,
    pub file_provider_materialize: ManuallyDrop<es_event_file_provider_materialize_t>,
    pub file_provider_update: ManuallyDrop<es_event_file_provider_update_t>,
    pub fork: ManuallyDrop<es_event_fork_t>,
    pub get_task: ManuallyDrop<es_event_get_task_t>,
    pub iokit_open: ManuallyDrop<es_event_iokit_open_t>,
    pub kextload: ManuallyDrop<es_event_kextload_t>,
    pub kextunload: ManuallyDrop<es_event_kextunload_t>,
    pub link: ManuallyDrop<es_event_link_t>,
    pub lookup: ManuallyDrop<es_event_lookup_t>,
    pub mmap: ManuallyDrop<es_event_mmap_t>,
    pub mount: ManuallyDrop<es_event_mount_t>,
    pub mprotect: ManuallyDrop<es_event_mprotect_t>,
    pub open: ManuallyDrop<es_event_open_t>,
    pub readlink: ManuallyDrop<es_event_readlink_t>,
    pub rename: ManuallyDrop<es_event_rename_t>,
    pub setattrlist: ManuallyDrop<es_event_setattrlist_t>,
    pub setextattr: ManuallyDrop<es_event_setextattr_t>,
    pub setflags: ManuallyDrop<es_event_setflags_t>,
    pub setmode: ManuallyDrop<es_event_setmode_t>,
    pub setowner: ManuallyDrop<es_event_setowner_t>,
    pub signal: ManuallyDrop<es_event_signal_t>,
    pub truncate: ManuallyDrop<es_event_truncate_t>,
    pub unlink: ManuallyDrop<es_event_unlink_t>,
    pub unmount: ManuallyDrop<es_event_unmount_t>,
    pub write: ManuallyDrop<es_event_write_t>,

    // 10.15.1
    #[cfg(feature = "macos_10_15_1")]
    pub access: ManuallyDrop<es_event_access_t>,
    #[cfg(feature = "macos_10_15_1")]
    pub chdir: ManuallyDrop<es_event_chdir_t>,
    #[cfg(feature = "macos_10_15_1")]
    pub chroot: ManuallyDrop<es_event_chroot_t>,
    #[cfg(feature = "macos_10_15_1")]
    pub clone: ManuallyDrop<es_event_clone_t>,
    #[cfg(feature = "macos_10_15_1")]
    pub deleteextattr: ManuallyDrop<es_event_deleteextattr_t>,
    #[cfg(feature = "macos_10_15_1")]
    pub dup: ManuallyDrop<es_event_dup_t>,
    #[cfg(feature = "macos_10_15_1")]
    pub fcntl: ManuallyDrop<es_event_fcntl_t>,
    #[cfg(feature = "macos_10_15_1")]
    pub fsgetpath: ManuallyDrop<es_event_fsgetpath_t>,
    #[cfg(feature = "macos_10_15_1")]
    pub getattrlist: ManuallyDrop<es_event_getattrlist_t>,
    #[cfg(feature = "macos_10_15_1")]
    pub getextattr: ManuallyDrop<es_event_getextattr_t>,
    #[cfg(feature = "macos_10_15_1")]
    pub listextattr: ManuallyDrop<es_event_listextattr_t>,
    #[cfg(feature = "macos_10_15_1")]
    pub readdir: ManuallyDrop<es_event_readdir_t>,
    #[cfg(feature = "macos_10_15_1")]
    pub remount: ManuallyDrop<es_event_remount_t>,
    #[cfg(feature = "macos_10_15_1")]
    pub setacl: ManuallyDrop<es_event_setacl_t>,
    #[cfg(feature = "macos_10_15_1")]
    pub settime: ManuallyDrop<es_event_settime_t>,
    #[cfg(feature = "macos_10_15_1")]
    pub stat: ManuallyDrop<es_event_stat_t>,
    #[cfg(feature = "macos_10_15_1")]
    pub uipc_bind: ManuallyDrop<es_event_uipc_bind_t>,
    #[cfg(feature = "macos_10_15_1")]
    pub uipc_connect: ManuallyDrop<es_event_uipc_connect_t>,
    #[cfg(feature = "macos_10_15_1")]
    pub utimes: ManuallyDrop<es_event_utimes_t>,

    // 10.15.4
    #[cfg(feature = "macos_10_15_4")]
    pub proc_check: ManuallyDrop<es_event_proc_check_t>,
    #[cfg(feature = "macos_10_15_4")]
    pub pty_close: ManuallyDrop<es_event_pty_close_t>,
    #[cfg(feature = "macos_10_15_4")]
    pub pty_grant: ManuallyDrop<es_event_pty_grant_t>,

    // 11.0.0
    #[cfg(feature = "macos_11_0_0")]
    pub cs_invalidated: ManuallyDrop<es_event_cs_invalidated_t>,
    #[cfg(feature = "macos_11_0_0")]
    pub get_task_name: ManuallyDrop<es_event_get_task_name_t>,
    #[cfg(feature = "macos_11_0_0")]
    pub proc_suspend_resume: ManuallyDrop<es_event_proc_suspend_resume_t>,
    #[cfg(feature = "macos_11_0_0")]
    pub remote_thread_create: ManuallyDrop<es_event_remote_thread_create_t>,
    #[cfg(feature = "macos_11_0_0")]
    pub searchfs: ManuallyDrop<es_event_searchfs_t>,
    #[cfg(feature = "macos_11_0_0")]
    pub trace: ManuallyDrop<es_event_trace_t>,

    // 11.3.0
    #[cfg(feature = "macos_11_3_0")]
    pub get_task_read: ManuallyDrop<es_event_get_task_read_t>,
    #[cfg(feature = "macos_11_3_0")]
    pub get_task_inspect: ManuallyDrop<es_event_get_task_inspect_t>,

    // 12.0.0
    #[cfg(feature = "macos_12_0_0")]
    pub copyfile: ManuallyDrop<es_event_copyfile_t>,
    #[cfg(feature = "macos_12_0_0")]
    pub setgid: ManuallyDrop<es_event_setgid_t>,
    #[cfg(feature = "macos_12_0_0")]
    pub setuid: ManuallyDrop<es_event_setuid_t>,
    #[cfg(feature = "macos_12_0_0")]
    pub setegid: ManuallyDrop<es_event_setegid_t>,
    #[cfg(feature = "macos_12_0_0")]
    pub seteuid: ManuallyDrop<es_event_seteuid_t>,
    #[cfg(feature = "macos_12_0_0")]
    pub setregid: ManuallyDrop<es_event_setregid_t>,
    #[cfg(feature = "macos_12_0_0")]
    pub setreuid: ManuallyDrop<es_event_setreuid_t>,
    // Events added in macOS 13.0 or later use nonnull pointers.
    //
    // 13.0.0
    #[cfg(feature = "macos_13_0_0")]
    pub authentication: ShouldNotBeNull<es_event_authentication_t>,
    #[cfg(feature = "macos_13_0_0")]
    pub xp_malware_detected: ShouldNotBeNull<es_event_xp_malware_detected_t>,
    #[cfg(feature = "macos_13_0_0")]
    pub xp_malware_remediated: ShouldNotBeNull<es_event_xp_malware_remediated_t>,
    #[cfg(feature = "macos_13_0_0")]
    pub lw_session_login: ShouldNotBeNull<es_event_lw_session_login_t>,
    #[cfg(feature = "macos_13_0_0")]
    pub lw_session_logout: ShouldNotBeNull<es_event_lw_session_logout_t>,
    #[cfg(feature = "macos_13_0_0")]
    pub lw_session_lock: ShouldNotBeNull<es_event_lw_session_lock_t>,
    #[cfg(feature = "macos_13_0_0")]
    pub lw_session_unlock: ShouldNotBeNull<es_event_lw_session_unlock_t>,
    #[cfg(feature = "macos_13_0_0")]
    pub screensharing_attach: ShouldNotBeNull<es_event_screensharing_attach_t>,
    #[cfg(feature = "macos_13_0_0")]
    pub screensharing_detach: ShouldNotBeNull<es_event_screensharing_detach_t>,
    #[cfg(feature = "macos_13_0_0")]
    pub openssh_login: ShouldNotBeNull<es_event_openssh_login_t>,
    #[cfg(feature = "macos_13_0_0")]
    pub openssh_logout: ShouldNotBeNull<es_event_openssh_logout_t>,
    #[cfg(feature = "macos_13_0_0")]
    pub login_login: ShouldNotBeNull<es_event_login_login_t>,
    #[cfg(feature = "macos_13_0_0")]
    pub login_logout: ShouldNotBeNull<es_event_login_logout_t>,
    #[cfg(feature = "macos_13_0_0")]
    pub btm_launch_item_add: ShouldNotBeNull<es_event_btm_launch_item_add_t>,
    #[cfg(feature = "macos_13_0_0")]
    pub btm_launch_item_remove: ShouldNotBeNull<es_event_btm_launch_item_remove_t>,
}

/// Indicates the result of the ES subsystem authorization process
#[repr(C)]
#[must_use]
#[derive(Copy, Clone)]
pub struct es_result_t {
    pub result_type: es_result_type_t,
    pub result: es_result_t_anon_0,
}

/// See [`es_result_t`]
#[repr(C)]
#[derive(Copy, Clone)]
pub union es_result_t_anon_0 {
    pub auth: es_auth_result_t,
    pub flags: u32,
    _reserved: [u8; 32],
}

/// This is the top level datatype that encodes information sent from the ES subsystem to its
/// clients. Each security event being processed by the ES subsystem will be encoded in an
/// `es_message_t`. A message can be an authorization request or a notification of an event that has
/// already taken place.
///
/// For events that can be authorized there are unique `NOTIFY` and `AUTH` event types for the same
/// event data, eg: `event.exec` is the correct union label for both `ES_EVENT_TYPE_AUTH_EXEC` and
/// `ES_EVENT_TYPE_NOTIFY_EXEC` event types.
///
/// For fields marked only available in specific message versions, all access must be guarded at
/// runtime by checking the value of the message version field, e.g.
///
/// ```ignore
/// if msg.version >= 2 {
///     acl = unsafe { msg.event.create.acl };
/// }
/// ```
///
/// Fields using Mach time are in the resolution matching the ES client's architecture. This means
/// they can be compared to `mach_absolute_time()` and converted to nanoseconds with the help of
/// mach_timebase_info(). Further note that on Apple silicon, x86_64 clients running under Rosetta 2
/// will see Mach times in a different resolution than native arm64 clients. For more information on
/// differences regarding Mach time on Apple silicon and Intel-based Mac computers, see "Addressing
/// Architectural Differences in Your macOS Code":
/// <https://developer.apple.com/documentation/apple_silicon/addressing_architectural_differences_in_your_macos_code>
///
/// ## Rust implementation notes
///
/// [`RefEncode`] is currently implemented with the encoding left unknown explicitly. If
/// `es_message_t` needs to be encoded for Objective C messages, this will require changes.
#[repr(C)]
pub struct es_message_t {
    /// Indicates the message version; some fields are not available and must not be accessed unless
    /// the message version is equal to or higher than the message version at which the field was
    /// introduced.
    pub version: u32,
    /// The time at which the event was generated
    pub time: timespec,
    /// The Mach absolute time at which the event was generated
    pub mach_time: u64,
    /// The Mach absolute time before which an auth event must be responded to. If a client fails
    /// to respond to auth events prior to the `deadline`, the client will be killed. Each message
    /// can contain its own unique deadline, and some deadlines can vary substantially. Clients must
    /// take care to inspect the deadline value of each message to know how much time is allotted
    /// for processing.
    pub deadline: u64,
    /// Describes the process that took the action
    pub process: ShouldNotBeNull<es_process_t>,
    /// Per-client, per-event-type sequence number that can be inspected to detect whether the
    /// kernel had to drop events for this client. When no events are dropped for this client,
    /// `seq_num` increments by 1 for every message of that event type. When events have been
    /// dropped, the difference between the last seen sequence number of that event type plus 1 and
    /// `seq_num` of the received message indicates the number of events that had to be dropped.
    /// Dropped events generally indicate that more events were generated in the kernel than the
    /// client was able to handle.
    ///
    /// See `global_seq_num`.
    ///
    /// Field available only if message version >= 2.
    #[cfg(feature = "macos_10_15_1")]
    pub seq_num: u64,
    /// Indicates if the action field is an auth or notify action
    pub action_type: es_action_type_t,
    /// For auth events, contains the opaque auth ID that must be supplied when responding to the
    /// event. For notify events, describes the result of the action.
    pub action: es_message_t_anon_0,
    /// Indicates which event struct is defined in the event union
    pub event_type: es_event_type_t,
    /// Contains data specific to the event type
    pub event: es_events_t,
    /// Describes the thread that took the action. May be `NULL` when thread is not applicable,
    /// for example for trace events that describe the traced process calling `ptrace(PT_TRACE_ME)`
    /// or for cs invalidated events that are a result of another process calling
    /// `csops(CS_OPS_MARKINVALID)`.
    ///
    /// Field available only if message version >= 4.
    #[cfg(feature = "macos_11_0_0")]
    pub thread: *mut es_thread_t,
    /// Per-client sequence number that can be inspected to detect whether the kernel had to
    /// drop events for this client. When no events are dropped for this client, `global_seq_num`
    /// increments by 1 for every message. When events have been dropped, the difference between the
    /// last seen global sequence number and the `global_seq_num` of the received message indicates
    /// the number of events that had to be dropped. Dropped events generally indicate that more
    /// events were generated in the kernel than the client was able to handle.
    ///
    /// See also: `seq_num`.
    ///
    /// Field available only if message version >= 4.
    #[cfg(feature = "macos_11_0_0")]
    pub global_seq_num: u64,
    /// Opaque data that must not be accessed directly
    _opaque: [u64; 0],
}

should_not_be_null_fields!(es_message_t; process -> es_process_t);
#[cfg(feature = "macos_11_0_0")]
null_fields!(es_message_t; thread -> es_thread_t);

unsafe impl RefEncode for es_message_t {
    const ENCODING_REF: Encoding = Encoding::Pointer(&Encoding::Unknown);
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union es_message_t_anon_0 {
    pub auth: es_event_id_t,
    pub notify: es_result_t,
}

#[link(name = "EndpointSecurity", kind = "dylib")]
extern "C" {
    /// Calculate the size of an [`es_message_t`].
    ///
    /// This function **MUST NOT** be used in conjunction with attempting to copy an `es_message_t`
    /// (e.g. by using the reported size in order to `malloc(3)` a buffer, and `memcpy(3)` an
    /// existing `es_message_t` into that buffer). Doing so will result in use-after-free bugs.
    ///
    ///
    #[cfg_attr(
        feature = "macos_11_0_0",
        doc = "**Deprecated in macOS 11+**: Please use [`es_retain_message()`] to retain an `es_message_t`."
    )]
    #[cfg_attr(
        not(feature = "macos_11_0_0"),
        doc = "**Deprecated in macOS 11+**: Please use `es_retain_message()` to retain an `es_message_t`."
    )]
    ///
    /// - `msg`: The message for which the size will be calculated
    /// - Returns the size of the message
    pub fn es_message_size(msg: &es_message_t) -> usize;

    /// Retains an [`es_message_t`], returning a non-const pointer to the given `es_message_t` for
    /// compatibility with existing code.
    ///
    /// It is invalid to attempt to write to the returned `es_message_t`, despite being non-`const`,
    /// and doing so will result in a crash.
    ///
    #[cfg_attr(
        feature = "macos_11_0_0",
        doc = "**Deprecated in macOS 11+**: Please use [`es_retain_message()`] to retain an `es_message_t`."
    )]
    #[cfg_attr(
        not(feature = "macos_11_0_0"),
        doc = "**Deprecated in macOS 11+**: Please use `es_retain_message()` to retain an `es_message_t`."
    )]
    ///
    /// - `msg`: The message to be retained
    /// - Returns a non-const pointer to the retained `es_message_t`
    ///
    /// The caller must release the memory with [`es_free_message()`]
    pub fn es_copy_message(msg: &es_message_t) -> *mut es_message_t;

    /// Releases the memory associated with the given [`es_message_t`] that was retained via
    /// [`es_copy_message()`]
    ///
    #[cfg_attr(
        feature = "macos_11_0_0",
        doc = "**Deprecated in macOS 11+**: Please use [`es_retain_message()`] to retain an `es_message_t`."
    )]
    #[cfg_attr(
        not(feature = "macos_11_0_0"),
        doc = "**Deprecated in macOS 11+**: Please use `es_retain_message()` to retain an `es_message_t`."
    )]
    ///
    /// - `msg`: The message to be released
    pub fn es_free_message(msg: &es_message_t);

    /// Retains the given [`es_message_t`], extending its lifetime until released with [`es_release_message()`].
    ///
    /// - `msg`: The message to be retained
    ///
    /// It is necessary to retain a message when the `es_message_t` provided in the event handler block of
    /// [`es_new_client()`][super::es_new_client] will be processed asynchronously.
    ///
    /// Available for macos 11+
    #[cfg(feature = "macos_11_0_0")]
    pub fn es_retain_message(msg: &es_message_t);

    /// Releases the given [`es_message_t`] that was previously retained with [`es_retain_message()`]
    ///
    /// - `msg`: The message to be released
    ///
    /// Available for macos 11+
    #[cfg(feature = "macos_11_0_0")]
    pub fn es_release_message(msg: &es_message_t);

    /// Get the number of arguments in a message containing an [`es_event_exec_t`]
    ///
    /// - `event`: The `es_event_exec_t` being inspected
    /// - Returns the number of arguments
    pub fn es_exec_arg_count(event: &es_event_exec_t) -> u32;

    /// Get the number of environment variables in a message containing an [`es_event_exec_t`]
    ///
    /// - `event`: The `es_event_exec_t` being inspected
    /// - Returns The number of environment variables
    pub fn es_exec_env_count(event: &es_event_exec_t) -> u32;

    /// Get the number of file descriptors in a message containing an [`es_event_exec_t`]
    ///
    /// - `event`: The `es_event_exec_t` being inspected
    /// - Returns The number of file descriptors
    ///
    /// Available for macos 11+
    #[cfg(feature = "macos_11_0_0")]
    pub fn es_exec_fd_count(event: &es_event_exec_t) -> u32;

    /// Get the argument at the specified position in the message containing an [`es_event_exec_t`]
    ///
    /// - `event`: The `es_event_exec_t` being inspected
    /// - `index`: Index of the argument to retrieve (starts from 0)
    /// - Returns an `es_string_token_t` containing a pointer to the argument and its length.
    ///   This is a zero-allocation operation. The returned pointer **must not** outlive `exec_event`.
    ///
    /// Reading an an argument where `index` >= [`es_exec_arg_count()`] is undefined
    pub fn es_exec_arg(event: &es_event_exec_t, index: u32) -> es_string_token_t;

    /// Get the environment variable at the specified position in the message containing an
    /// [`es_event_exec_t`]
    ///
    /// - `event`: The `es_event_exec_t` being inspected
    /// - `index`: Index of the environment variable to retrieve (starts from 0)
    /// - Returns an `es_string_token_t` containing a pointer to the environment variable and its length.
    ///   This is zero-allocation operation. The returned pointer **must not** outlive `exec_event`.
    ///
    /// Reading an an env where `index` >= [`es_exec_env_count()`] is undefined.
    pub fn es_exec_env(event: &es_event_exec_t, index: u32) -> es_string_token_t;

    /// Get the file descriptor at the specified position in the message containing an
    /// [`es_event_exec_t`]
    ///
    /// - `event`: The `es_event_exec_t` being inspected
    /// - `index`: Index of the file descriptor to retrieve (starts from 0)
    /// - Returns a pointer to an `es_fd_t` describing the file descriptor.
    ///   This is zero-allocation operation. The returned pointer **must not** outlive `exec_event`.
    ///
    /// Reading an fd where `index` >= [`es_exec_fd_count()`] is undefined
    ///
    /// Available for macos 11+
    #[cfg(feature = "macos_11_0_0")]
    pub fn es_exec_fd(event: &es_event_exec_t, index: u32) -> ShouldNotBeNull<es_fd_t>;
}
