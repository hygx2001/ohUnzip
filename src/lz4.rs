use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

const LZ4_FRAME_MAGIC: u32 = 0x184D_2204;
const LZ4_SKIPPABLE_MAGIC_MIN: u32 = 0x184D_2A50;
const LZ4_SKIPPABLE_MAGIC_MAX: u32 = 0x184D_2A5F;
const HISTORY_WINDOW: usize = 64 * 1024;

#[derive(Debug)]
pub enum Lz4Error {
    Cancelled,
    Message(String),
}

/// Validates an LZ4 Frame header (`04 22 4D 18` + FLG + BD + optional ContentSize/DictID + xxHash32 HC).
pub fn is_valid_lz4_frame_header(header: &[u8]) -> bool {
    if header.len() < 7 {
        return false;
    }
    let magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    if magic != LZ4_FRAME_MAGIC {
        return false;
    }

    let flg = header[4];
    let bd = header[5];

    // Version bits (7..6) MUST be 01; reserved bit 1 MUST be 0
    if (flg & 0xC0) != 0x40 || (flg & 0x02) != 0 {
        return false;
    }
    // Reserved bits of BD (bit 7 and bits 3..0) MUST be 0; Block MaxSize code MUST be 4..=7
    if (bd & 0x8F) != 0 {
        return false;
    }
    let block_max_id = (bd >> 4) & 0x07;
    if !(4..=7).contains(&block_max_id) {
        return false;
    }

    let has_content_size = (flg & 0x08) != 0;
    let has_dict_id = (flg & 0x01) != 0;
    let desc_len = 2 + if has_content_size { 8 } else { 0 } + if has_dict_id { 4 } else { 0 };
    let hc_idx = 4 + desc_len;
    if header.len() <= hc_idx {
        return false;
    }

    let expected_hc = ((xxh32_oneshot(&header[4..hc_idx], 0) >> 8) & 0xFF) as u8;
    header[hc_idx] == expected_hc
}

/// Decompresses an LZ4 Frame file (`src`) into `dst` with cancellation and max-size protection.
/// Supports concatenated frames, skippable frames, independent & dependent blocks,
/// uncompressed blocks, and validates header / block / content xxHash32 checksums.
pub fn decompress_file(
    src: &Path,
    dst: &Path,
    max_output_bytes: u64,
    cancel_flag: &AtomicBool,
) -> Result<u64, Lz4Error> {
    let in_file =
        File::open(src).map_err(|e| Lz4Error::Message(format!("无法读取 LZ4 文件: {e}")))?;
    let out_file =
        File::create(dst).map_err(|e| Lz4Error::Message(format!("无法创建 LZ4 解压目标文件: {e}")))?;

    let mut reader = BufReader::with_capacity(256 * 1024, in_file);
    let mut writer = BufWriter::with_capacity(256 * 1024, out_file);

    let total = decompress_stream(&mut reader, &mut writer, max_output_bytes, cancel_flag)?;
    writer
        .flush()
        .map_err(|e| Lz4Error::Message(format!("写入 LZ4 解压输出失败: {e}")))?;
    Ok(total)
}

pub fn decompress_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    max_output_bytes: u64,
    cancel_flag: &AtomicBool,
) -> Result<u64, Lz4Error> {
    let mut total_written: u64 = 0;
    let mut decoded_any_frame = false;

    loop {
        if cancel_flag.load(Ordering::Relaxed) {
            return Err(Lz4Error::Cancelled);
        }

        let Some(magic_bytes) = read_exact_or_eof(reader, 4)
            .map_err(|e| Lz4Error::Message(format!("读取 LZ4 帧头失败: {e}")))?
        else {
            break;
        };

        let magic = u32::from_le_bytes([
            magic_bytes[0],
            magic_bytes[1],
            magic_bytes[2],
            magic_bytes[3],
        ]);

        // Skippable frame
        if (LZ4_SKIPPABLE_MAGIC_MIN..=LZ4_SKIPPABLE_MAGIC_MAX).contains(&magic) {
            let skip_len = read_u32_le(reader)
                .map_err(|e| Lz4Error::Message(format!("读取 LZ4 跳过帧长度失败: {e}")))?
                as u64;
            let mut limited = reader.take(skip_len);
            let skipped = io::copy(&mut limited, &mut io::sink())
                .map_err(|e| Lz4Error::Message(format!("跳过 LZ4 扩展帧失败: {e}")))?;
            if skipped != skip_len {
                return Err(Lz4Error::Message("LZ4 跳过帧数据不完整".into()));
            }
            continue;
        }

        if magic != LZ4_FRAME_MAGIC {
            if decoded_any_frame {
                return Err(Lz4Error::Message("LZ4 文件尾部存在无效帧头".into()));
            }
            return Err(Lz4Error::Message("不是有效的 LZ4 Frame 文件".into()));
        }

        decoded_any_frame = true;

        // Parse Frame Descriptor
        let mut flg_bd = [0u8; 2];
        reader
            .read_exact(&mut flg_bd)
            .map_err(|e| Lz4Error::Message(format!("读取 LZ4 描述符失败: {e}")))?;
        let flg = flg_bd[0];
        let bd = flg_bd[1];

        if (flg & 0xC0) != 0x40 || (flg & 0x02) != 0 {
            return Err(Lz4Error::Message("不支持的 LZ4 帧版本或标志位".into()));
        }
        if (bd & 0x8F) != 0 {
            return Err(Lz4Error::Message("无效的 LZ4 块大小描述符".into()));
        }

        let block_max_size: usize = match (bd >> 4) & 0x07 {
            4 => 64 * 1024,
            5 => 256 * 1024,
            6 => 1024 * 1024,
            7 => 4 * 1024 * 1024,
            _ => return Err(Lz4Error::Message("不支持的 LZ4 最大块尺寸".into())),
        };

        let block_indep = (flg & 0x20) != 0;
        let has_block_checksum = (flg & 0x10) != 0;
        let has_content_size = (flg & 0x08) != 0;
        let has_content_checksum = (flg & 0x04) != 0;
        let has_dict_id = (flg & 0x01) != 0;

        let mut desc = Vec::with_capacity(14);
        desc.extend_from_slice(&flg_bd);

        let expected_content_size = if has_content_size {
            let mut sz_buf = [0u8; 8];
            reader
                .read_exact(&mut sz_buf)
                .map_err(|e| Lz4Error::Message(format!("读取 LZ4 内容大小失败: {e}")))?;
            desc.extend_from_slice(&sz_buf);
            Some(u64::from_le_bytes(sz_buf))
        } else {
            None
        };

        if has_dict_id {
            let mut dict_buf = [0u8; 4];
            reader
                .read_exact(&mut dict_buf)
                .map_err(|e| Lz4Error::Message(format!("读取 LZ4 字典 ID 失败: {e}")))?;
            desc.extend_from_slice(&dict_buf);
            if u32::from_le_bytes(dict_buf) != 0 {
                return Err(Lz4Error::Message("暂不支持依赖外部预置字典的 LZ4 文件".into()));
            }
        }

        let mut hc = [0u8; 1];
        reader
            .read_exact(&mut hc)
            .map_err(|e| Lz4Error::Message(format!("读取 LZ4 头校验和失败: {e}")))?;
        let calc_hc = ((xxh32_oneshot(&desc, 0) >> 8) & 0xFF) as u8;
        if hc[0] != calc_hc {
            return Err(Lz4Error::Message("LZ4 帧头校验和不匹配（文件可能损坏）".into()));
        }

        let mut content_hasher = Xxh32::new(0);
        let mut history: Vec<u8> = Vec::new();
        let mut comp_buf: Vec<u8> = Vec::new();
        let mut out_block: Vec<u8> = Vec::new();
        let mut frame_written: u64 = 0;

        // Decode data blocks until EndMark (0)
        loop {
            if cancel_flag.load(Ordering::Relaxed) {
                return Err(Lz4Error::Cancelled);
            }

            let block_hdr = read_u32_le(reader)
                .map_err(|e| Lz4Error::Message(format!("读取 LZ4 块头失败: {e}")))?;
            if block_hdr == 0 {
                break;
            }

            let uncompressed = (block_hdr & 0x8000_0000) != 0;
            let block_size = (block_hdr & 0x7FFF_FFFF) as usize;
            if block_size > block_max_size {
                return Err(Lz4Error::Message(format!(
                    "LZ4 数据块大小超出帧声明上限 ({block_size} > {block_max_size})"
                )));
            }

            comp_buf.resize(block_size, 0);
            reader
                .read_exact(&mut comp_buf)
                .map_err(|e| Lz4Error::Message(format!("读取 LZ4 数据块失败: {e}")))?;

            if has_block_checksum {
                let expected_crc = read_u32_le(reader)
                    .map_err(|e| Lz4Error::Message(format!("读取 LZ4 块校验和失败: {e}")))?;
                if xxh32_oneshot(&comp_buf, 0) != expected_crc {
                    return Err(Lz4Error::Message("LZ4 数据块校验失败（文件可能损坏）".into()));
                }
            }

            let decoded_slice: &[u8] = if uncompressed {
                &comp_buf
            } else {
                out_block.clear();
                decompress_lz4_block(&comp_buf, &history, block_max_size, &mut out_block)?;
                &out_block
            };

            frame_written = frame_written.saturating_add(decoded_slice.len() as u64);
            total_written = total_written.saturating_add(decoded_slice.len() as u64);
            if max_output_bytes > 0 && total_written > max_output_bytes {
                return Err(Lz4Error::Message(
                    "触发防压缩炸弹保护：LZ4 解压输出体积超过上限".into(),
                ));
            }

            if has_content_checksum {
                content_hasher.update(decoded_slice);
            }

            writer
                .write_all(decoded_slice)
                .map_err(|e| Lz4Error::Message(format!("写入 LZ4 解压数据失败: {e}")))?;

            if !block_indep {
                update_history(&mut history, decoded_slice);
            }
        }

        if has_content_checksum {
            let expected_crc = read_u32_le(reader)
                .map_err(|e| Lz4Error::Message(format!("读取 LZ4 内容校验和失败: {e}")))?;
            if content_hasher.finish() != expected_crc {
                return Err(Lz4Error::Message("LZ4 内容校验失败（文件可能损坏）".into()));
            }
        }

        if let Some(expected_sz) = expected_content_size {
            if frame_written != expected_sz {
                return Err(Lz4Error::Message(format!(
                    "LZ4 解压长度不匹配（预期 {expected_sz} 字节，实际 {frame_written} 字节）"
                )));
            }
        }
    }

    if !decoded_any_frame {
        return Err(Lz4Error::Message("LZ4 文件不包含有效数据帧".into()));
    }

    Ok(total_written)
}

fn update_history(history: &mut Vec<u8>, decoded: &[u8]) {
    if decoded.len() >= HISTORY_WINDOW {
        history.clear();
        history.extend_from_slice(&decoded[decoded.len() - HISTORY_WINDOW..]);
    } else {
        let total = history.len() + decoded.len();
        if total > HISTORY_WINDOW {
            history.drain(..total - HISTORY_WINDOW);
        }
        history.extend_from_slice(decoded);
    }
}

fn decompress_lz4_block(
    input: &[u8],
    history: &[u8],
    max_block_out: usize,
    out: &mut Vec<u8>,
) -> Result<(), Lz4Error> {
    let mut ip = 0usize;
    let in_len = input.len();

    while ip < in_len {
        let token = input[ip];
        ip += 1;

        // 1. Literal length
        let mut lit_len = (token >> 4) as usize;
        if lit_len == 15 {
            loop {
                if ip >= in_len {
                    return Err(Lz4Error::Message("LZ4 块字面量长度截断".into()));
                }
                let extra = input[ip] as usize;
                ip += 1;
                lit_len = lit_len
                    .checked_add(extra)
                    .ok_or_else(|| Lz4Error::Message("LZ4 块长度溢出".into()))?;
                if extra != 255 {
                    break;
                }
            }
        }

        if ip.checked_add(lit_len).is_none_or(|end| end > in_len) {
            return Err(Lz4Error::Message("LZ4 块字面量数据越界".into()));
        }
        if out.len().saturating_add(lit_len) > max_block_out {
            return Err(Lz4Error::Message("LZ4 解压块超出最大块尺寸".into()));
        }
        out.extend_from_slice(&input[ip..ip + lit_len]);
        ip += lit_len;

        // Per LZ4 block spec, the final sequence ends right after literals
        if ip == in_len {
            break;
        }

        // 2. Match offset (2-byte LE, 1..=65535)
        if ip + 2 > in_len {
            return Err(Lz4Error::Message("LZ4 块匹配偏移截断".into()));
        }
        let offset = u16::from_le_bytes([input[ip], input[ip + 1]]) as usize;
        ip += 2;
        if offset == 0 {
            return Err(Lz4Error::Message("LZ4 块包含无效的 0 偏移".into()));
        }

        // 3. Match length (4 + low nibble + optional extension bytes)
        let mut match_len = (token & 0x0F) as usize + 4;
        if (token & 0x0F) == 15 {
            loop {
                if ip >= in_len {
                    return Err(Lz4Error::Message("LZ4 块匹配长度截断".into()));
                }
                let extra = input[ip] as usize;
                ip += 1;
                match_len = match_len
                    .checked_add(extra)
                    .ok_or_else(|| Lz4Error::Message("LZ4 块匹配长度溢出".into()))?;
                if extra != 255 {
                    break;
                }
            }
        }

        if out.len().saturating_add(match_len) > max_block_out {
            return Err(Lz4Error::Message("LZ4 解压块超出最大块尺寸".into()));
        }

        // Copy match bytes, supporting both previous-block history (dependent blocks) and RLE overlap
        let total_avail = history.len() + out.len();
        if offset > total_avail {
            return Err(Lz4Error::Message("LZ4 块回溯偏移超出历史窗口".into()));
        }

        out.reserve(match_len);
        let mut remaining = match_len;

        // If the match starts inside `history` (dependent block mode)
        if offset > out.len() {
            let back_in_hist = offset - out.len();
            let hist_start = history.len() - back_in_hist;
            let from_hist = remaining.min(back_in_hist);
            out.extend_from_slice(&history[hist_start..hist_start + from_hist]);
            remaining -= from_hist;
        }

        // Copy remaining match bytes from `out` (byte-by-byte handles overlapping RLE matches cleanly)
        if remaining > 0 {
            let mut src_idx = out.len() - offset;
            for _ in 0..remaining {
                let b = out[src_idx];
                out.push(b);
                src_idx += 1;
            }
        }
    }

    Ok(())
}

fn read_u32_le<R: Read>(reader: &mut R) -> io::Result<u32> {
    let mut b = [0u8; 4];
    reader.read_exact(&mut b)?;
    Ok(u32::from_le_bytes(b))
}

fn read_exact_or_eof<R: Read>(reader: &mut R, len: usize) -> io::Result<Option<Vec<u8>>> {
    let mut buf = vec![0u8; len];
    let mut read_total = 0usize;
    while read_total < len {
        let n = reader.read(&mut buf[read_total..])?;
        if n == 0 {
            if read_total == 0 {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF",
            ));
        }
        read_total += n;
    }
    Ok(Some(buf))
}

// --- Pure-Rust streaming xxHash32 (RFC / official LZ4 spec) ---

const PRIME32_1: u32 = 0x9E37_79B1;
const PRIME32_2: u32 = 0x85EB_CA77;
const PRIME32_3: u32 = 0xC2B2_AE3D;
const PRIME32_4: u32 = 0x27D4_EB2F;
const PRIME32_5: u32 = 0x1656_67B1;

struct Xxh32 {
    seed: u32,
    total_len: u64,
    v1: u32,
    v2: u32,
    v3: u32,
    v4: u32,
    mem: [u8; 16],
    mem_len: usize,
}

impl Xxh32 {
    fn new(seed: u32) -> Self {
        Self {
            seed,
            total_len: 0,
            v1: seed.wrapping_add(PRIME32_1).wrapping_add(PRIME32_2),
            v2: seed.wrapping_add(PRIME32_2),
            v3: seed,
            v4: seed.wrapping_sub(PRIME32_1),
            mem: [0u8; 16],
            mem_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        if self.mem_len + data.len() < 16 {
            self.mem[self.mem_len..self.mem_len + data.len()].copy_from_slice(data);
            self.mem_len += data.len();
            return;
        }

        if self.mem_len > 0 {
            let fill = 16 - self.mem_len;
            self.mem[self.mem_len..16].copy_from_slice(&data[..fill]);
            let block = self.mem;
            self.process_stripe(&block);
            self.mem_len = 0;
            data = &data[fill..];
        }

        while data.len() >= 16 {
            self.process_stripe(&data[..16]);
            data = &data[16..];
        }

        if !data.is_empty() {
            self.mem[..data.len()].copy_from_slice(data);
            self.mem_len = data.len();
        }
    }

    #[inline]
    fn process_stripe(&mut self, stripe: &[u8]) {
        let k1 = u32::from_le_bytes([stripe[0], stripe[1], stripe[2], stripe[3]]);
        let k2 = u32::from_le_bytes([stripe[4], stripe[5], stripe[6], stripe[7]]);
        let k3 = u32::from_le_bytes([stripe[8], stripe[9], stripe[10], stripe[11]]);
        let k4 = u32::from_le_bytes([stripe[12], stripe[13], stripe[14], stripe[15]]);
        self.v1 = xxh32_round(self.v1, k1);
        self.v2 = xxh32_round(self.v2, k2);
        self.v3 = xxh32_round(self.v3, k3);
        self.v4 = xxh32_round(self.v4, k4);
    }

    fn finish(&self) -> u32 {
        let mut h32 = if self.total_len >= 16 {
            self.v1
                .rotate_left(1)
                .wrapping_add(self.v2.rotate_left(7))
                .wrapping_add(self.v3.rotate_left(12))
                .wrapping_add(self.v4.rotate_left(18))
        } else {
            self.seed.wrapping_add(PRIME32_5)
        };

        h32 = h32.wrapping_add(self.total_len as u32);

        let mut i = 0usize;
        while i + 4 <= self.mem_len {
            let k = u32::from_le_bytes([
                self.mem[i],
                self.mem[i + 1],
                self.mem[i + 2],
                self.mem[i + 3],
            ]);
            h32 = h32
                .wrapping_add(k.wrapping_mul(PRIME32_3))
                .rotate_left(17)
                .wrapping_mul(PRIME32_4);
            i += 4;
        }
        while i < self.mem_len {
            h32 = h32
                .wrapping_add((self.mem[i] as u32).wrapping_mul(PRIME32_5))
                .rotate_left(11)
                .wrapping_mul(PRIME32_1);
            i += 1;
        }

        h32 ^= h32 >> 15;
        h32 = h32.wrapping_mul(PRIME32_2);
        h32 ^= h32 >> 13;
        h32 = h32.wrapping_mul(PRIME32_3);
        h32 ^= h32 >> 16;
        h32
    }
}

#[inline]
fn xxh32_round(acc: u32, input: u32) -> u32 {
    acc.wrapping_add(input.wrapping_mul(PRIME32_2))
        .rotate_left(13)
        .wrapping_mul(PRIME32_1)
}

pub fn xxh32_oneshot(data: &[u8], seed: u32) -> u32 {
    let mut h = Xxh32::new(seed);
    h.update(data);
    h.finish()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Helper that builds a valid LZ4 Frame (uncompressed or simple compressed block) for tests.
    pub(crate) fn encode_lz4_frame_uncompressed(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&LZ4_FRAME_MAGIC.to_le_bytes());
        // FLG: version=01, B.Indep=1, B.Checksum=0, C.Size=1, C.Checksum=1, DictID=0 => 0x6C
        let mut desc = Vec::new();
        desc.push(0x6C);
        desc.push(0x40); // BD: 64KB max block
        desc.extend_from_slice(&(data.len() as u64).to_le_bytes());
        let hc = ((xxh32_oneshot(&desc, 0) >> 8) & 0xFF) as u8;
        out.extend_from_slice(&desc);
        out.push(hc);

        for chunk in data.chunks(64 * 1024) {
            let hdr = 0x8000_0000u32 | (chunk.len() as u32);
            out.extend_from_slice(&hdr.to_le_bytes());
            out.extend_from_slice(chunk);
        }
        out.extend_from_slice(&0u32.to_le_bytes()); // EndMark
        out.extend_from_slice(&xxh32_oneshot(data, 0).to_le_bytes()); // Content Checksum
        out
    }

    #[test]
    fn test_xxh32_known_vectors() {
        assert_eq!(xxh32_oneshot(b"", 0), 0x02CC_5D05);
        assert_eq!(xxh32_oneshot(b"hello", 0), 0xFB00_77F9);
        // Header descriptor from real LZ4 file (`6C 40 00 04 00 00 00 00 00 00` => HC = 0x56)
        let desc = [0x6Cu8, 0x40, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(((xxh32_oneshot(&desc, 0) >> 8) & 0xFF) as u8, 0x56);
    }

    #[test]
    fn test_lz4_frame_roundtrip_and_rle_match() {
        // 1. Uncompressed block frame roundtrip
        let payload = b"OhUnzip LZ4 Frame test payload! ".repeat(200);
        let frame = encode_lz4_frame_uncompressed(&payload);
        assert!(is_valid_lz4_frame_header(&frame));

        let mut out = Vec::new();
        let cancel = AtomicBool::new(false);
        let n = decompress_stream(&mut &frame[..], &mut out, 10 * 1024 * 1024, &cancel).unwrap();
        assert_eq!(n as usize, payload.len());
        assert_eq!(out, payload);

        // 2. Compressed block with overlapping RLE match: literal "AB" + match(offset=2, len=10) => "ABABABABABAB"
        let mut comp_frame = Vec::new();
        comp_frame.extend_from_slice(&LZ4_FRAME_MAGIC.to_le_bytes());
        let desc = [0x64u8, 0x40]; // B.Indep=1, C.Checksum=1
        comp_frame.extend_from_slice(&desc);
        comp_frame.push(((xxh32_oneshot(&desc, 0) >> 8) & 0xFF) as u8);
        // Token: 2 literals (0x20) + match len 10 - 4 = 6 (0x06) => 0x26
        // Literals: "AB", Offset: 2 LE (0x02, 0x00)
        let block = [0x26u8, b'A', b'B', 0x02, 0x00];
        comp_frame.extend_from_slice(&(block.len() as u32).to_le_bytes());
        comp_frame.extend_from_slice(&block);
        comp_frame.extend_from_slice(&0u32.to_le_bytes());
        let expected = b"ABABABABABAB";
        comp_frame.extend_from_slice(&xxh32_oneshot(expected, 0).to_le_bytes());

        let mut out2 = Vec::new();
        decompress_stream(&mut &comp_frame[..], &mut out2, 1024, &cancel).unwrap();
        assert_eq!(out2, expected);
    }
}
