//! Overlapped Named Pipe I/O shared by the RPC client and server.
//!
//! Each [`PipeEndpoint`] issues overlapped operations with its own event and
//! waits for them to complete, which gives blocking `Read`/`Write` semantics.
//! Separate endpoints for the same pipe can be used concurrently from
//! different threads, and reads can be given a timeout without the busy
//! polling (and Windows timer-resolution latency) of `PeekNamedPipe` + sleep.

use std::io::{self, Read, Write};
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::sync::Arc;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_OPERATION_ABORTED,
    ERROR_PIPE_NOT_CONNECTED, GetLastError, HANDLE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

struct Event(HANDLE);

// SAFETY: Event handles may be used from any thread.
unsafe impl Send for Event {}

impl Event {
    fn new() -> io::Result<Self> {
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(event))
        }
    }
}

impl Drop for Event {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

/// Blocking I/O on a pipe handle opened with `FILE_FLAG_OVERLAPPED`.
pub struct PipeEndpoint {
    pipe: Arc<OwnedHandle>,
    event: Event,
    read_timeout: Option<Duration>,
}

impl PipeEndpoint {
    pub fn new(pipe: Arc<OwnedHandle>) -> io::Result<Self> {
        Ok(Self {
            pipe,
            event: Event::new()?,
            read_timeout: None,
        })
    }

    pub fn pipe(&self) -> &Arc<OwnedHandle> {
        &self.pipe
    }

    /// Make reads fail with `ErrorKind::TimedOut` if no data arrives in time.
    /// Reads still return as soon as any data is available.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.read_timeout = timeout;
    }

    fn transfer(
        &mut self,
        timeout: Option<Duration>,
        start: impl FnOnce(HANDLE, *mut OVERLAPPED) -> i32,
    ) -> io::Result<usize> {
        let handle = self.pipe.as_raw_handle() as HANDLE;
        let mut overlapped = unsafe { std::mem::zeroed::<OVERLAPPED>() };
        overlapped.hEvent = self.event.0;
        if start(handle, &mut overlapped) == 0 {
            let err = unsafe { GetLastError() };
            if err != ERROR_IO_PENDING {
                return Err(io::Error::from_raw_os_error(err as i32));
            }
        }

        let mut cancelled = false;
        if let Some(timeout) = timeout {
            let millis = timeout.as_millis().clamp(1, u32::MAX as u128 - 1) as u32;
            if unsafe { WaitForSingleObject(self.event.0, millis) } != WAIT_OBJECT_0 {
                unsafe { CancelIoEx(handle, &overlapped) };
                cancelled = true;
            }
        }

        // Always wait for completion: `overlapped` must outlive the operation.
        // If cancellation raced with completion, the transferred data is kept.
        let mut transferred = 0u32;
        if unsafe { GetOverlappedResult(handle, &overlapped, &mut transferred, 1) } == 0 {
            let err = io::Error::last_os_error();
            if cancelled && err.raw_os_error() == Some(ERROR_OPERATION_ABORTED as i32) {
                return Err(io::ErrorKind::TimedOut.into());
            }
            return Err(err);
        }
        Ok(transferred as usize)
    }
}

impl Read for PipeEndpoint {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = buf.len().min(u32::MAX as usize) as u32;
        let result = self.transfer(self.read_timeout, |handle, overlapped| unsafe {
            ReadFile(
                handle,
                buf.as_mut_ptr(),
                len,
                std::ptr::null_mut(),
                overlapped,
            )
        });
        match result {
            // A closed or disconnected pipe, or I/O cancelled to shut the
            // endpoint down, is end of stream.
            Err(e)
                if [
                    ERROR_BROKEN_PIPE,
                    ERROR_PIPE_NOT_CONNECTED,
                    ERROR_OPERATION_ABORTED,
                ]
                .iter()
                .any(|&code| e.raw_os_error() == Some(code as i32)) =>
            {
                Ok(0)
            }
            other => other,
        }
    }
}

impl Write for PipeEndpoint {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = buf.len().min(u32::MAX as usize) as u32;
        self.transfer(None, |handle, overlapped| unsafe {
            WriteFile(handle, buf.as_ptr(), len, std::ptr::null_mut(), overlapped)
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::FromRawHandle;
    use std::time::Instant;

    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX};
    use windows_sys::Win32::System::Pipes::{CreateNamedPipeW, PIPE_TYPE_BYTE, PIPE_WAIT};

    /// Create a connected (server, client) pair of overlapped pipe handles.
    fn pipe_pair() -> (Arc<OwnedHandle>, Arc<OwnedHandle>) {
        let name = format!(
            r"\\.\pipe\ykman-pipe-test-{}-{:?}",
            std::process::id(),
            Instant::now()
        );
        let name_w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let server = unsafe {
            CreateNamedPipeW(
                name_w.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_WAIT,
                1,
                4096,
                4096,
                0,
                std::ptr::null(),
            )
        };
        assert_ne!(server, INVALID_HANDLE_VALUE);
        let server = unsafe { OwnedHandle::from_raw_handle(server) };
        let client = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_OVERLAPPED)
            .open(&name)
            .unwrap();
        (Arc::new(server), Arc::new(OwnedHandle::from(client)))
    }

    #[test]
    fn read_timeout_preserves_data_and_returns_promptly() {
        let (server, client) = pipe_pair();
        let mut reader = PipeEndpoint::new(server).unwrap();
        reader.set_read_timeout(Some(Duration::from_millis(10)));
        let mut writer = PipeEndpoint::new(client).unwrap();
        let mut buf = [0u8; 16];

        let err = reader.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);

        writer.write_all(b"hello").unwrap();
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");

        let worker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(5));
            writer.write_all(b"world").unwrap();
            writer
        });
        let mut received = Vec::new();
        while received.len() < 5 {
            match reader.read(&mut buf) {
                Ok(n) => received.extend_from_slice(&buf[..n]),
                Err(e) => assert_eq!(e.kind(), io::ErrorKind::TimedOut),
            }
        }
        assert_eq!(received, b"world");
        drop(worker.join().unwrap());

        // Closing the other end is end of stream.
        assert_eq!(reader.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn write_completes_while_read_is_pending_on_same_handle() {
        let (server, client) = pipe_pair();
        let mut server_reader = PipeEndpoint::new(server.clone()).unwrap();
        let mut server_writer = PipeEndpoint::new(server).unwrap();
        let mut client = PipeEndpoint::new(client).unwrap();

        let pending = std::thread::spawn(move || {
            let mut buf = [0u8; 16];
            let n = server_reader.read(&mut buf).unwrap();
            buf[..n].to_vec()
        });
        std::thread::sleep(Duration::from_millis(20));

        server_writer.write_all(b"response").unwrap();
        let mut buf = [0u8; 16];
        let n = client.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"response");

        client.write_all(b"request").unwrap();
        assert_eq!(pending.join().unwrap(), b"request");
    }
}
