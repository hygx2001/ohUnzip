use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    println!("cargo:rerun-if-changed=build.rs");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let ico_path = PathBuf::from("assets/icon.ico");
    if !ico_path.exists() {
        return;
    }

    let ico_bytes = fs::read(&ico_path).expect("failed to read assets/icon.ico");
    let res_bytes = build_windows_res_from_ico(&ico_bytes).expect("invalid assets/icon.ico");

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let res_path = out_dir.join("oh_unzip_icon.res");
    fs::write(&res_path, res_bytes).expect("failed to write oh_unzip_icon.res");

    println!("cargo:rustc-link-arg-bins={}", res_path.display());
}

/// Converts a standard `.ico` file into a compiled Windows `.res` binary containing
/// `RT_ICON` entries (IDs 1..=N) and `RT_GROUP_ICON` (ID 1), which MSVC `link.exe`
/// links directly into the `.exe` without needing external `rc.exe`.
fn build_windows_res_from_ico(ico: &[u8]) -> Result<Vec<u8>, &'static str> {
    if ico.len() < 6 {
        return Err("ico too short");
    }
    let reserved = u16::from_le_bytes([ico[0], ico[1]]);
    let ico_type = u16::from_le_bytes([ico[2], ico[3]]);
    let count = u16::from_le_bytes([ico[4], ico[5]]) as usize;
    if reserved != 0 || ico_type != 1 || count == 0 {
        return Err("bad ico header");
    }
    if ico.len() < 6 + count * 16 {
        return Err("truncated ico directory");
    }

    let mut res = Vec::new();
    // Standard 32-byte empty resource header record required at start of `.res` files
    res.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x00, // DataSize = 0
        0x20, 0x00, 0x00, 0x00, // HeaderSize = 32
        0xFF, 0xFF, 0x00, 0x00, // Type = 0
        0xFF, 0xFF, 0x00, 0x00, // Name = 0
        0x00, 0x00, 0x00, 0x00, // DataVersion
        0x00, 0x00,             // MemoryFlags
        0x00, 0x00,             // LanguageId
        0x00, 0x00, 0x00, 0x00, // Version
        0x00, 0x00, 0x00, 0x00, // Characteristics
    ]);

    let mut group_data = Vec::with_capacity(6 + count * 14);
    group_data.extend_from_slice(&0u16.to_le_bytes());
    group_data.extend_from_slice(&1u16.to_le_bytes());
    group_data.extend_from_slice(&(count as u16).to_le_bytes());

    for i in 0..count {
        let entry_off = 6 + i * 16;
        let width = ico[entry_off];
        let height = ico[entry_off + 1];
        let color_count = ico[entry_off + 2];
        let entry_res = ico[entry_off + 3];
        let planes = u16::from_le_bytes([ico[entry_off + 4], ico[entry_off + 5]]);
        let bit_count = u16::from_le_bytes([ico[entry_off + 6], ico[entry_off + 7]]);
        let bytes_in_res = u32::from_le_bytes([
            ico[entry_off + 8],
            ico[entry_off + 9],
            ico[entry_off + 10],
            ico[entry_off + 11],
        ]);
        let img_off = u32::from_le_bytes([
            ico[entry_off + 12],
            ico[entry_off + 13],
            ico[entry_off + 14],
            ico[entry_off + 15],
        ]) as usize;

        let end = img_off
            .checked_add(bytes_in_res as usize)
            .ok_or("overflow")?;
        if end > ico.len() {
            return Err("image slice out of bounds");
        }
        let img_data = &ico[img_off..end];
        let icon_id = (i + 1) as u16;

        // RT_ICON = 3
        push_res_entry(&mut res, 3, icon_id, img_data);

        // GRPICONDIRENTRY (14 bytes)
        group_data.push(width);
        group_data.push(height);
        group_data.push(color_count);
        group_data.push(entry_res);
        group_data.extend_from_slice(&planes.to_le_bytes());
        group_data.extend_from_slice(&bit_count.to_le_bytes());
        group_data.extend_from_slice(&bytes_in_res.to_le_bytes());
        group_data.extend_from_slice(&icon_id.to_le_bytes());
    }

    // RT_GROUP_ICON = 14, ID = 1 (gpui-pre-windows loads resource ID 1!)
    push_res_entry(&mut res, 14, 1, &group_data);

    Ok(res)
}

fn push_res_entry(out: &mut Vec<u8>, res_type: u16, res_id: u16, data: &[u8]) {
    let header_size: u32 = 32;
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&header_size.to_le_bytes());
    // Type ordinal
    out.extend_from_slice(&0xFFFFu16.to_le_bytes());
    out.extend_from_slice(&res_type.to_le_bytes());
    // Name ordinal
    out.extend_from_slice(&0xFFFFu16.to_le_bytes());
    out.extend_from_slice(&res_id.to_le_bytes());
    // DataVersion (4), MemoryFlags (2: MOVEABLE|PURE|DISCARDABLE = 0x1030), LanguageId (2: 0x0409), Version (4), Characteristics (4)
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0x1030u16.to_le_bytes());
    out.extend_from_slice(&0x0409u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());

    out.extend_from_slice(data);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}
