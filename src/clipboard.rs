//! Putting an indicator where the analyst can paste it.
//!
//! Every desktop has a clipboard and none of them share an API, so this shells
//! out to whatever the platform provides — and says whether one answered, so the
//! caller can tell the user rather than fail in silence.
//!
//! Windows is the exception: there it asks the system itself ([`win32`]).
//! `clip.exe` reads its input in the console's code page, not UTF-8, so anything
//! but ASCII — an internationalised domain, say — came out as other letters;
//! and a console program started from a windowed one flashes a console.

/// Put `text` on the system clipboard — on Windows through the system's own
/// calls, elsewhere by piping it to the platform's clipboard tool. Returns
/// whether it got there (Linux tries Wayland then X11 tools).
///
/// One `cfg` arm compiles and the rest vanish, so which one is *last* depends on
/// the platform — each has to return rather than fall out of the block as a tail.
#[allow(clippy::needless_return)]
pub(crate) fn copy_to_clipboard(text: &str) -> bool {
    #[cfg(target_os = "windows")]
    {
        return win32::set_text(text);
    }
    #[cfg(target_os = "macos")]
    {
        return pipe_to("pbcopy", &[], text);
    }
    #[cfg(target_os = "linux")]
    {
        return pipe_to("wl-copy", &[], text)
            || pipe_to("xclip", &["-selection", "clipboard"], text)
            || pipe_to("xsel", &["--clipboard", "--input"], text);
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        let _ = text;
        false
    }
}

/// Spawn `cmd args` and write `text` to its stdin — the shape every clipboard
/// tool takes. `false` if the tool is absent or exits non-zero.
#[allow(dead_code)]
fn pipe_to(cmd: &str, args: &[&str], text: &str) -> bool {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let Ok(mut child) = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    if let Some(mut stdin) = child.stdin.take() {
        if stdin.write_all(text.as_bytes()).is_err() {
            return false;
        }
    }
    child.wait().map(|s| s.success()).unwrap_or(false)
}

/// The Windows clipboard, through the calls the system gives for it. Declared
/// here rather than taken from a crate: it is a handful of functions.
#[cfg(target_os = "windows")]
pub(crate) mod win32 {
    use std::ffi::c_void;
    use std::ptr::null_mut;

    /// Text as UTF-16, ended with a zero.
    const CF_UNICODETEXT: u32 = 13;
    const GMEM_MOVEABLE: u32 = 0x0002;

    #[link(name = "user32")]
    extern "system" {
        fn OpenClipboard(owner: *mut c_void) -> i32;
        fn EmptyClipboard() -> i32;
        fn SetClipboardData(format: u32, memory: *mut c_void) -> *mut c_void;
        fn CloseClipboard() -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GlobalAlloc(flags: u32, bytes: usize) -> *mut c_void;
        fn GlobalLock(memory: *mut c_void) -> *mut c_void;
        fn GlobalUnlock(memory: *mut c_void) -> i32;
        fn GlobalFree(memory: *mut c_void) -> *mut c_void;
    }

    /// Open the clipboard, waiting a moment for whoever has it: only one
    /// program can at a time, and a clipboard manager takes it on every copy.
    fn open() -> bool {
        for _ in 0..20 {
            // SAFETY: no window owns the clipboard for us; none is needed.
            if unsafe { OpenClipboard(null_mut()) } != 0 {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        false
    }

    /// Put `text` on the clipboard, in place of what is there.
    pub(crate) fn set_text(text: &str) -> bool {
        // A zero ends the text, so one inside it would cut it short.
        let wide: Vec<u16> = text.encode_utf16().filter(|&u| u != 0).chain(std::iter::once(0)).collect();
        if !open() {
            return false;
        }
        // SAFETY: the clipboard is open, and is closed on every way out. The
        // memory is as long as `wide`, is written while locked, and belongs to
        // the system once SetClipboardData has taken it — it is freed here
        // only when that did not happen.
        unsafe {
            let mut set = false;
            if EmptyClipboard() != 0 {
                let memory = GlobalAlloc(GMEM_MOVEABLE, wide.len() * std::mem::size_of::<u16>());
                if !memory.is_null() {
                    let to = GlobalLock(memory) as *mut u16;
                    if !to.is_null() {
                        std::ptr::copy_nonoverlapping(wide.as_ptr(), to, wide.len());
                        GlobalUnlock(memory);
                        set = !SetClipboardData(CF_UNICODETEXT, memory).is_null();
                    }
                    if !set {
                        GlobalFree(memory);
                    }
                }
            }
            CloseClipboard();
            set
        }
    }
}
