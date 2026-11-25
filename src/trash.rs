use std::path::Path;

/// Move a file to the OS Recycle Bin / Trash safely (never permanently deletes).
pub fn move_to_trash(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }

    #[cfg(windows)]
    {
        move_to_trash_windows(path)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        Err("当前系统暂不支持移入回收站".into())
    }
}

#[cfg(windows)]
fn move_to_trash_windows(path: &Path) -> Result<(), String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;

    #[repr(C)]
    #[allow(non_snake_case)]
    struct SHFILEOPSTRUCTW {
        hwnd: *mut core::ffi::c_void,
        wFunc: u32,
        pFrom: *const u16,
        pTo: *const u16,
        fFlags: u16,
        fAnyOperationsAborted: i32,
        hNameMappings: *mut core::ffi::c_void,
        lpszProgressTitle: *const u16,
    }

    #[link(name = "shell32")]
    unsafe extern "system" {
        fn SHFileOperationW(lpFileOp: *mut SHFILEOPSTRUCTW) -> i32;
    }

    const FO_DELETE: u32 = 0x0003;
    const FOF_SILENT: u16 = 0x0004;
    const FOF_NOCONFIRMATION: u16 = 0x0010;
    const FOF_ALLOWUNDO: u16 = 0x0040;
    const FOF_NOERRORUI: u16 = 0x0400;

    // SHFileOperationW requires a double-null-terminated UTF-16 string
    let mut wide: Vec<u16> = OsStr::new(path).encode_wide().collect();
    wide.push(0);
    wide.push(0);

    let mut op = SHFILEOPSTRUCTW {
        hwnd: ptr::null_mut(),
        wFunc: FO_DELETE,
        pFrom: wide.as_ptr(),
        pTo: ptr::null(),
        fFlags: FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI,
        fAnyOperationsAborted: 0,
        hNameMappings: ptr::null_mut(),
        lpszProgressTitle: ptr::null(),
    };

    let ret = unsafe { SHFileOperationW(&mut op) };
    if ret == 0 && op.fAnyOperationsAborted == 0 {
        Ok(())
    } else {
        Err(format!("移入回收站失败 (code {ret})"))
    }
}
