use std::io;
use std::process::{Child, Command};

#[cfg(target_os = "windows")]
mod platform {
    use super::*;
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, NTSTATUS};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject,
    };
    use windows_sys::Win32::System::Threading::{CREATE_NO_WINDOW, CREATE_SUSPENDED};

    #[link(name = "ntdll")]
    unsafe extern "system" {
        #[link_name = "NtResumeProcess"]
        fn nt_resume_process(process: HANDLE) -> NTSTATUS;
        #[link_name = "RtlNtStatusToDosError"]
        fn rtl_nt_status_to_dos_error(status: NTSTATUS) -> u32;
    }

    struct Handle(HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    pub struct ProcessTree(Handle);

    impl ProcessTree {
        pub fn spawn(command: &mut Command) -> io::Result<(Child, Self)> {
            let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if job.is_null() {
                return Err(io::Error::last_os_error());
            }
            let tree = Self(Handle(job));
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if unsafe {
                SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            // Assign the suspended child before it can create descendants outside the job.
            let mut child = command
                .creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW)
                .spawn()?;
            let setup = (|| {
                if unsafe { AssignProcessToJobObject(job, child.as_raw_handle()) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                // Child exposes the process handle, while its primary thread is still suspended.
                let status = unsafe { nt_resume_process(child.as_raw_handle()) };
                if status < 0 {
                    return Err(io::Error::from_raw_os_error(unsafe {
                        rtl_nt_status_to_dos_error(status) as i32
                    }));
                }
                Ok(())
            })();
            if let Err(error) = setup {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
            Ok((child, tree))
        }

        pub fn terminate(&self) -> io::Result<()> {
            if unsafe { TerminateJobObject(self.0.0, 1) } == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::os::unix::process::CommandExt;

    pub struct ProcessTree(libc::pid_t);

    impl ProcessTree {
        pub fn spawn(command: &mut Command) -> io::Result<(Child, Self)> {
            let child = command.process_group(0).spawn()?;
            let tree = Self(child.id() as libc::pid_t);
            Ok((child, tree))
        }

        pub fn terminate(&self) -> io::Result<()> {
            if unsafe { libc::kill(-self.0, libc::SIGKILL) } == 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                Ok(())
            } else {
                Err(error)
            }
        }
    }

    impl Drop for ProcessTree {
        fn drop(&mut self) {
            let _ = self.terminate();
        }
    }
}

pub use platform::ProcessTree;
