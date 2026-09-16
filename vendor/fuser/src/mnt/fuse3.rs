use std::ffi::CString;
use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::fd::BorrowedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use std::sync::Arc;

use crate::SessionACL;
use crate::dev_fuse::DevFuse;
use crate::mnt::MountOption;
use crate::mnt::fuse3_sys::fuse_lowlevel_ops;
use crate::mnt::fuse3_sys::fuse_session_destroy;
use crate::mnt::fuse3_sys::fuse_session_fd;
use crate::mnt::fuse3_sys::fuse_session_mount;
use crate::mnt::fuse3_sys::fuse_session_new;
use crate::mnt::fuse3_sys::fuse_session_unmount;
use crate::mnt::with_fuse_args;

/// Ensures that an os error is never 0/Success
fn ensure_last_os_error() -> io::Error {
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(0) => io::Error::new(io::ErrorKind::Other, "Unspecified Error"),
        _ => err,
    }
}

#[derive(Debug)]
pub(crate) struct MountImpl {
    fuse_session: Option<*mut c_void>,
    mountpoint: CString,
}
impl MountImpl {
    pub(crate) fn new(
        mnt: &Path,
        options: &[MountOption],
        acl: SessionACL,
    ) -> io::Result<(Arc<DevFuse>, MountImpl)> {
        let mnt = CString::new(mnt.as_os_str().as_bytes()).unwrap();
        with_fuse_args(options, acl, |args| {
            let ops = fuse_lowlevel_ops::default();

            let fuse_session = unsafe {
                fuse_session_new(
                    args,
                    &ops as *const _,
                    size_of::<fuse_lowlevel_ops>(),
                    ptr::null_mut(),
                )
            };
            if fuse_session.is_null() {
                return Err(io::Error::last_os_error());
            }
            let result = unsafe { fuse_session_mount(fuse_session, mnt.as_ptr()) };
            if result != 0 {
                let err = ensure_last_os_error();
                unsafe { fuse_session_destroy(fuse_session) };
                return Err(err);
            }
            let fd = unsafe { fuse_session_fd(fuse_session) };
            if fd < 0 {
                let err = io::Error::last_os_error();
                unsafe {
                    fuse_session_unmount(fuse_session);
                    fuse_session_destroy(fuse_session);
                }
                return Err(err);
            }
            let fd = unsafe { BorrowedFd::borrow_raw(fd) };
            // We dup the fd here as the existing fd is owned by the fuse_session, and we
            // don't want it being closed out from under us:
            let owned = match fd.try_clone_to_owned() {
                Ok(owned) => owned,
                Err(err) => {
                    unsafe {
                        fuse_session_unmount(fuse_session);
                        fuse_session_destroy(fuse_session);
                    }
                    return Err(err);
                }
            };
            let file = File::from(owned);
            let mount = MountImpl {
                fuse_session: Some(fuse_session),
                mountpoint: mnt.clone(),
            };
            Ok((Arc::new(DevFuse(file)), mount))
        })
    }

    pub(crate) fn umount_impl(&mut self) -> io::Result<()> {
        let Some(session) = self.fuse_session.take() else {
            return Ok(());
        };
        if let Err(err) = crate::mnt::libc_umount(&self.mountpoint) {
            // Linux always returns EPERM for non-root users.  We have to let the
            // library go through the setuid-root "fusermount -u" to unmount.
            if err == nix::errno::Errno::EPERM {
                #[cfg(target_os = "linux")]
                unsafe {
                    fuse_session_unmount(session);
                    fuse_session_destroy(session);
                    return Ok(());
                }
            }
            self.fuse_session = Some(session);
            return Err(err.into());
        }
        // The kernel mount is gone but libfuse still owns the session
        // allocation: unmount (best-effort, already unmounted) then destroy,
        // on every platform. Previously only the Linux EPERM fallback did
        // this, leaking the session on macOS success paths.
        unsafe {
            fuse_session_unmount(session);
            fuse_session_destroy(session);
        }
        Ok(())
    }
}
unsafe impl Send for MountImpl {}

impl Drop for MountImpl {
    fn drop(&mut self) {
        if let Some(session) = self.fuse_session.take() {
            unsafe {
                fuse_session_unmount(session);
                fuse_session_destroy(session);
            }
        }
    }
}
