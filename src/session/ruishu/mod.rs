//! 重庆大学 SSO 瑞数 6 安全 Cookie (Cookie T / CtLgrmkSWHBZP) 纯算加解密与生成引擎

use std::{
    sync::LazyLock,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{
    Engine,
    alphabet::Alphabet,
    engine::{GeneralPurpose, general_purpose::NO_PAD},
};

use crate::errors::session::SessionError;

mod coder;
mod r2mka;

/// 由 mainjs 源码、`$_ts.nsd` 与会话 `cd` 纯算 Tag 7 的 16 位校验和 `code_uid`
///
/// 该值由服务端逐位校验（翻一位即 400），输入含本会话的 `keys[33]`/`keys[34]`，
/// 因此每个会话都要重算，不能按部署缓存。
pub fn code_uid(mainjs: &str, nsd: u32, cd: &str) -> Result<u16, SessionError> {
    let keys = extract_keys(cd)?;
    let mut coder = coder::Coder::new(nsd, mainjs);
    coder.run();
    coder.code_uid(&keys)
}

/// 由 mainjs 源码、`$_ts.nsd` 与会话 `cd` 纯算出 Cookie T 与 basearr。
///
/// 时间戳取站点下发的 `keys[21]`：Tag 10 对时间敏感，服务端时间更贴近判定。
///
/// ```no_run
/// # use rsmycqu::session::ruishu::generate_cookie_t_auto;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mainjs = std::fs::read_to_string("mainjs.js")?;
/// let cd = "页面中的 $_ts.cd";
/// let nsd = 85762;
/// let (cookie_t, basearr) = generate_cookie_t_auto(&mainjs, nsd, cd)?;
/// assert!(!cookie_t.is_empty());
/// assert!(!basearr.is_empty());
/// # Ok(())
/// # }
/// ```
pub fn generate_cookie_t_auto(
    mainjs: &str,
    nsd: u32,
    cd: &str,
) -> Result<(String, Vec<u8>), SessionError> {
    let keys = extract_keys(cd)?;
    keys.session_key()?;
    let mut coder = coder::Coder::new(nsd, mainjs);
    coder.run();
    let code_uid = coder.code_uid(&keys)?;
    let tag2 = coder.tag2(&keys)?;
    let t1 = keys.key_num(21)?;
    let basearr = build_inner_cipher(&keys, t1, code_uid, tag2, None)?;
    let cookie_t = generate_cookie_t_with_keys(&keys, &basearr, t1, t1 + 2, None)?;
    Ok((cookie_t, basearr))
}

/// 86 字符主字符表
const BASESTR: &[u8; 86] =
    b"qrcklmDoExthWJiHAp1sVYKU3RFMQw8IGfPO92bvLNj-7zXBaSnu0TC6gy_4Ze5d{}|~ !#$%()*+,.;=?@[]^";

/// Cookie T 所用 base64 引擎（主表前 64 字符，无填充）
const RUISHU_B64: GeneralPurpose = {
    const ALPHABET: Alphabet =
        match Alphabet::new("qrcklmDoExthWJiHAp1sVYKU3RFMQw8IGfPO92bvLNj-7zXBaSnu0TC6gy_4Ze5d") {
            Ok(alphabet) => alphabet,
            Err(_) => panic!("invalid Cookie T base64 alphabet"),
        };
    GeneralPurpose::new(&ALPHABET, NO_PAD)
};

/// 站点常量密钥
const K16: [u8; 16] = [
    0x0a, 0xaf, 0x65, 0x01, 0x4a, 0x42, 0x4d, 0x15, 0x42, 0xf8, 0xe9, 0x27, 0xe2, 0x4a, 0xdf, 0xc4,
];

/// 密钥分段提取异或掩码
const MASK: [u8; 8] = [51, 2, 0x36, 0x34, 2, 0x36, 0x34, 48];

const DK: [[u8; 256]; 6] = {
    let mut a = [[0u8; 256]; 6];
    let mut i = 0;
    while i < BASESTR.len() {
        let c = BASESTR[i] as usize;
        a[0][c] = (i << 2) as u8;
        a[1][c] = (i >> 4) as u8;
        a[2][c] = ((i & 15) << 4) as u8;
        a[3][c] = (i >> 2) as u8;
        a[4][c] = ((i & 3) << 6) as u8;
        a[5][c] = i as u8;
        i += 1;
    }
    a
};

const CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut j = 0;
        while j < 8 {
            if (c & 1) != 0 {
                c = 0xedb8_8320 ^ (c >> 1);
            } else {
                c >>= 1;
            }
            j += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

type CfgTables = ([[u32; 256]; 5], [[u32; 256]; 5]);

static CFGNUM: LazyLock<CfgTables> = LazyLock::new(make_cfgnum);

fn make_cfgnum() -> CfgTables {
    let mut arr1 = [[0u32; 256]; 5];
    let mut arr2 = [[0u32; 256]; 5];
    let mut one = [0usize; 256];
    let mut two = [0usize; 256];

    for i in 0..256 {
        let o = (i << 1) ^ if (i >> 7) != 0 { 283 } else { 0 };
        one[i] = o;
        two[o ^ i] = i;
    }

    let mut visited = [false; 256];
    let mut i = 0usize;
    let mut j = 0usize;
    while !visited[i] {
        visited[i] = true;
        let mut temp = (j ^ (j << 1) ^ (j << 2) ^ (j << 3) ^ (j << 4)) as u32;
        temp = (temp >> 8) ^ (temp & 255) ^ 99;
        arr1[4][i] = temp;
        arr2[4][temp as usize] = i as u32;

        let step_i = if one[i] != 0 { one[i] } else { 1 };
        let step_j = if two[j] != 0 { two[j] } else { 1 };
        i ^= step_i;
        j = step_j;
    }

    for idx in 0..256 {
        arr2[4][arr1[4][idx] as usize] = idx as u32;
    }

    for idx in 0..256 {
        let o1 = one[idx];
        let o2 = one[o1];
        let o3 = one[o2];
        let mut ele1 = (o3 as u32).wrapping_mul(16843009)
            ^ (o2 as u32).wrapping_mul(65537)
            ^ (o1 as u32).wrapping_mul(257)
            ^ (idx as u32).wrapping_mul(16843008);
        let mut ele2 = (one[arr1[4][idx] as usize] as u32).wrapping_mul(257)
            ^ arr1[4][idx].wrapping_mul(16843008);

        for col in 0..4 {
            ele2 = ele2.rotate_right(8);
            arr1[col][idx] = ele2;
            ele1 = ele1.rotate_right(8);
            arr2[col][arr1[4][idx] as usize] = ele1;
        }
    }

    (arr1, arr2)
}

/// 解码 `$_ts.cd` 字符串为原始字节流
fn decode_cd(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity((bytes.len() / 4) * 3);
    for chunk in bytes.chunks(4) {
        let c0 = chunk[0] as usize;
        let c1 = *chunk.get(1).unwrap_or(&0) as usize;
        let c2 = *chunk.get(2).unwrap_or(&0) as usize;
        let c3 = *chunk.get(3).unwrap_or(&0) as usize;

        if chunk.len() >= 2 {
            out.push(DK[0][c0] | DK[1][c1]);
        }
        if chunk.len() >= 3 {
            out.push(DK[2][c1] | DK[3][c2]);
        }
        if chunk.len() >= 4 {
            out.push(DK[4][c2] | DK[5][c3]);
        }
    }
    out
}

/// 解析 varint 编码的长度分段
fn get_lens(a: &[u8], mut i: usize) -> Option<(usize, usize)> {
    if i >= a.len() {
        return None;
    }
    let x = a[i] as usize;
    i += 1;
    let l = if (x & 128) == 0 {
        x
    } else if (x & 192) == 128 {
        if i >= a.len() {
            return None;
        }
        let l = ((x & 63) << 8) | (a[i] as usize);
        i += 1;
        l
    } else if (x & 224) == 192 {
        if i + 1 >= a.len() {
            return None;
        }
        let l = ((x & 31) << 16) | ((a[i] as usize) << 8) | (a[i + 1] as usize);
        i += 2;
        l
    } else {
        x
    };
    Some((l, i))
}

/// 瑞数 51 组密钥解析结果
#[derive(Debug, Clone, PartialEq, Eq)]
struct RuishuKeys {
    /// 51 组密钥数据
    keys: Vec<Vec<u8>>,
}

impl RuishuKeys {
    /// 取第 `idx` 组密钥
    fn key(&self, idx: usize) -> Result<&[u8], SessionError> {
        self.keys
            .get(idx)
            .map(Vec::as_slice)
            .ok_or_else(|| SessionError::RuishuError {
                msg: format!("keys[{idx}] not found"),
            })
    }

    /// 取第 `idx` 组密钥并解析为十进制整数
    fn key_num(&self, idx: usize) -> Result<u32, SessionError> {
        std::str::from_utf8(self.key(idx)?)
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| SessionError::RuishuError {
                msg: format!("keys[{idx}] is not a decimal integer"),
            })
    }

    /// 获取站点加密常量密钥（`keys[16]`）
    fn site_key(&self) -> Result<&[u8], SessionError> {
        self.key(16)
    }

    /// 获取当前会话密钥（`keys[2]`，要求固定 48 字节）
    fn session_key(&self) -> Result<&[u8; 48], SessionError> {
        let k = self.key(2)?;
        k.try_into().map_err(|_| SessionError::RuishuError {
            msg: format!("keys[2] length must be 48, got {}", k.len()),
        })
    }
}

/// 从页面 `$_ts.cd` 提取 51 组密钥
fn extract_keys(cd: &str) -> Result<RuishuKeys, SessionError> {
    let a = decode_cd(cd);
    if a.len() < 2 {
        return Err(SessionError::RuishuError {
            msg: "decoded cd too short".to_string(),
        });
    }
    let e = (((a[0] as usize) << 8) | (a[1] as usize)) + 2;
    if e + 8 > a.len() {
        return Err(SessionError::RuishuError {
            msg: "invalid cd payload offset".to_string(),
        });
    }
    let s = &a[e..];
    let mut o = [0u8; 8];
    for i in 0..8 {
        o[i] = s[i] ^ MASK[i];
    }
    let ans: Vec<u8> = s.iter().enumerate().map(|(i, &b)| b ^ o[i % 8]).collect();
    if ans.is_empty() {
        return Err(SessionError::RuishuError {
            msg: "empty ans buffer".to_string(),
        });
    }
    let key_count = ans[0] as usize;

    for step in [2u8, 1u8] {
        let mut keys = Vec::with_capacity(key_count);
        let mut op = 1usize;
        let mut ok = true;
        for _ in 0..key_count {
            let (gap, next_op) = if step == 2 {
                if op + 1 >= ans.len() {
                    ok = false;
                    break;
                }
                let gap = ((ans[op] as usize) << 8) | (ans[op + 1] as usize);
                (gap, op + 2)
            } else {
                match get_lens(&ans, op) {
                    Some((gap, next_op)) => (gap, next_op),
                    None => {
                        ok = false;
                        break;
                    }
                }
            };
            if next_op + gap > ans.len() {
                ok = false;
                break;
            }
            keys.push(ans[next_op..next_op + gap].to_vec());
            op = next_op + gap;
        }
        if !ok {
            continue;
        }
        let chk_pass = (29..=32).all(|idx| keys.get(idx).map(|k| k.len()) == Some(4));
        if chk_pass {
            return Ok(RuishuKeys { keys });
        }
    }

    Err(SessionError::RuishuError {
        msg: "failed to extract 51 keys passing self-check".to_string(),
    })
}

/// 计算 IEEE 802.3 标准 CRC32 校验和
fn crc32(d: &[u8]) -> u32 {
    let mut c = 0xffff_ffffu32;
    for &b in d {
        c = (c >> 8) ^ CRC_TABLE[((c ^ (b as u32)) & 0xff) as usize];
    }
    !c
}

/// 根据 16 字节密钥展开计算 44 轮加解密轮密钥
fn get_cfg(numarr: &[u8]) -> Result<([u32; 44], [u32; 44]), SessionError> {
    if numarr.len() != 16 {
        return Err(SessionError::RuishuError {
            msg: format!("cipher key must be 16 bytes, got {}", numarr.len()),
        });
    }
    let (chunks, _) = numarr.as_chunks::<4>();
    let mut ret = [0u32; 44];
    for i in 0..4 {
        ret[i] = u32::from_be_bytes(chunks[i]);
    }
    let cfgnum_0_4 = &CFGNUM.0[4];

    let mut j: u32 = 1;
    for i in 4..44 {
        let mut temp = ret[i - 1];
        if i % 4 == 0 {
            temp = (cfgnum_0_4[(temp >> 24) as usize] << 24)
                ^ (cfgnum_0_4[((temp >> 16) & 255) as usize] << 16)
                ^ (cfgnum_0_4[((temp >> 8) & 255) as usize] << 8)
                ^ cfgnum_0_4[(temp & 255) as usize];
            temp = (temp << 8) ^ (temp >> 24) ^ (j << 24);
            j = (j << 1) ^ ((j >> 7) * 283);
        }
        let prev = ret[i - 4];
        ret[i] = prev ^ temp;
    }

    let mut arr = [0u32; 44];
    let mut j_idx = 0usize;
    let mut i_idx = 44usize;
    while i_idx > 0 && j_idx < 44 {
        let temp = ret[if (j_idx & 3) != 0 { i_idx } else { i_idx - 4 }];
        if i_idx <= 4 || j_idx < 4 {
            arr[j_idx] = temp;
        } else {
            arr[j_idx] = CFGNUM.1[0][cfgnum_0_4[(temp >> 24) as usize] as usize]
                ^ CFGNUM.1[1][cfgnum_0_4[((temp >> 16) & 255) as usize] as usize]
                ^ CFGNUM.1[2][cfgnum_0_4[((temp >> 8) & 255) as usize] as usize]
                ^ CFGNUM.1[3][cfgnum_0_4[(temp & 255) as usize] as usize];
        }
        j_idx += 1;
        i_idx -= 1;
    }

    Ok((ret, arr))
}

/// 执行单分组自定义 S-box 与置换运算
fn encode(cfg: &[u32; 44], val: [u32; 4], idx: usize, cfgnum: &[[u32; 256]; 5]) -> [u32; 4] {
    let mut arr = [0u32; 4];
    let mut one = val[0] ^ cfg[0];
    let mut two = val[if idx != 0 { 3 } else { 1 }] ^ cfg[1];
    let mut three = val[2] ^ cfg[2];
    let mut four = val[if idx != 0 { 1 } else { 3 }] ^ cfg[3];
    let mut cursor = 4usize;

    for _ in 0..(cfg.len() / 4 - 2) {
        let none = cfgnum[0][(one >> 24) as usize]
            ^ cfgnum[1][((two >> 16) & 255) as usize]
            ^ cfgnum[2][((three >> 8) & 255) as usize]
            ^ cfgnum[3][(four & 255) as usize]
            ^ cfg[cursor];
        let ntwo = cfgnum[0][(two >> 24) as usize]
            ^ cfgnum[1][((three >> 16) & 255) as usize]
            ^ cfgnum[2][((four >> 8) & 255) as usize]
            ^ cfgnum[3][(one & 255) as usize]
            ^ cfg[cursor + 1];
        let nthree = cfgnum[0][(three >> 24) as usize]
            ^ cfgnum[1][((four >> 16) & 255) as usize]
            ^ cfgnum[2][((one >> 8) & 255) as usize]
            ^ cfgnum[3][(two & 255) as usize]
            ^ cfg[cursor + 2];
        four = cfgnum[0][(four >> 24) as usize]
            ^ cfgnum[1][((one >> 16) & 255) as usize]
            ^ cfgnum[2][((two >> 8) & 255) as usize]
            ^ cfgnum[3][(three & 255) as usize]
            ^ cfg[cursor + 3];
        cursor += 4;
        one = none;
        two = ntwo;
        three = nthree;
    }

    for i in 0..4 {
        let out_idx = if idx != 0 { [0, 3, 2, 1][i] } else { i };
        arr[out_idx] = (cfgnum[4][(one >> 24) as usize] << 24)
            ^ (cfgnum[4][((two >> 16) & 255) as usize] << 16)
            ^ (cfgnum[4][((three >> 8) & 255) as usize] << 8)
            ^ cfgnum[4][(four & 255) as usize]
            ^ cfg[cursor];
        cursor += 1;
        let next_one = two;
        let next_two = three;
        let next_three = four;
        let next_four = one;
        one = next_one;
        two = next_two;
        three = next_three;
        four = next_four;
    }

    arr
}

/// 执行模式 1（CBC 分组加密，PKCS#7 填充）
///
/// `iv_words` 为 `None` 时使用零 IV 且不前置 IV（内层载荷加密），否则前置该 IV。
fn encrypt_mode1(
    valarr: &[u8],
    keyarr: &[u8],
    iv_words: Option<[u32; 4]>,
) -> Result<Vec<u8>, SessionError> {
    let (cfg_enc, _) = get_cfg(keyarr)?;
    let fill = 16 - (valarr.len() % 16);
    let total_len = if iv_words.is_some() { 16 } else { 0 } + valarr.len() + fill;
    let mut out = Vec::with_capacity(total_len);

    let mut arr = [0u32; 4];
    if let Some(iv) = iv_words {
        arr = iv;
        for w in iv {
            out.extend_from_slice(&w.to_be_bytes());
        }
    }

    let (blocks, remainder) = valarr.as_chunks::<16>();
    for block in blocks {
        let (words, _) = block.as_chunks::<4>();
        let current = [
            u32::from_be_bytes(words[0]) ^ arr[0],
            u32::from_be_bytes(words[1]) ^ arr[1],
            u32::from_be_bytes(words[2]) ^ arr[2],
            u32::from_be_bytes(words[3]) ^ arr[3],
        ];
        arr = encode(&cfg_enc, current, 0, &CFGNUM.0);
        for w in arr {
            out.extend_from_slice(&w.to_be_bytes());
        }
    }

    let mut last_block = [fill as u8; 16];
    last_block[..remainder.len()].copy_from_slice(remainder);
    let (words, _) = last_block.as_chunks::<4>();
    let current = [
        u32::from_be_bytes(words[0]) ^ arr[0],
        u32::from_be_bytes(words[1]) ^ arr[1],
        u32::from_be_bytes(words[2]) ^ arr[2],
        u32::from_be_bytes(words[3]) ^ arr[3],
    ];
    arr = encode(&cfg_enc, current, 0, &CFGNUM.0);
    for w in arr {
        out.extend_from_slice(&w.to_be_bytes());
    }

    Ok(out)
}

/// 执行模式 2 (CBC 分组解密与填充剥离)
fn decrypt_mode2(valarr: &[u8], keyarr: &[u8], flag: bool) -> Result<Vec<u8>, SessionError> {
    let (_, cfg_dec) = get_cfg(keyarr)?;
    if !valarr.len().is_multiple_of(16) {
        return Err(SessionError::RuishuError {
            msg: format!(
                "ciphertext length must be a multiple of 16 bytes, got {}",
                valarr.len()
            ),
        });
    }
    let min_len = if flag { 32 } else { 16 };
    if valarr.len() < min_len {
        return Err(SessionError::RuishuError {
            msg: format!(
                "valarr too short for decryption: expected at least {min_len} bytes, got {}",
                valarr.len()
            ),
        });
    }

    let (blocks, _) = valarr.as_chunks::<16>();
    let (mut arrsub, cipher_blocks) = if flag {
        let (iv_words, _) = blocks[0].as_chunks::<4>();
        (
            [
                u32::from_be_bytes(iv_words[0]),
                u32::from_be_bytes(iv_words[1]),
                u32::from_be_bytes(iv_words[2]),
                u32::from_be_bytes(iv_words[3]),
            ],
            &blocks[1..],
        )
    } else {
        ([0u32; 4], blocks)
    };

    let mut ret = Vec::with_capacity(cipher_blocks.len() * 16);
    for block in cipher_blocks {
        let (words, _) = block.as_chunks::<4>();
        let next = [
            u32::from_be_bytes(words[0]),
            u32::from_be_bytes(words[1]),
            u32::from_be_bytes(words[2]),
            u32::from_be_bytes(words[3]),
        ];
        let mut val = encode(&cfg_dec, next, 1, &CFGNUM.1);
        val[0] ^= arrsub[0];
        val[1] ^= arrsub[1];
        val[2] ^= arrsub[2];
        val[3] ^= arrsub[3];
        for w in val {
            ret.extend_from_slice(&w.to_be_bytes());
        }
        arrsub = next;
    }

    let pad = match ret.last() {
        Some(&p) if (1..=16).contains(&p) && (p as usize) <= ret.len() => p as usize,
        _ => {
            return Err(SessionError::RuishuError {
                msg: "invalid PKCS#7 padding: pad length out of bounds".to_string(),
            });
        }
    };
    if !ret[ret.len() - pad..].iter().all(|&b| b == pad as u8) {
        return Err(SessionError::RuishuError {
            msg: "invalid PKCS#7 padding: mismatching padding bytes".to_string(),
        });
    }
    ret.truncate(ret.len() - pad);
    Ok(ret)
}
/// 使用 Cookie T 字符表编码字节流为 Base64 字符串
fn encode_base64(arr: &[u8]) -> String {
    RUISHU_B64.encode(arr)
}

/// 解码 Base64 字符串（自动兼容并剥离 `'a'` 或 `'0'` 前缀）
fn decode_base64(str: &str) -> Result<Vec<u8>, SessionError> {
    let body = str
        .strip_prefix('a')
        .or_else(|| str.strip_prefix('0'))
        .unwrap_or(str);
    RUISHU_B64
        .decode(body)
        .map_err(|e| SessionError::RuishuError {
            msg: format!("invalid Cookie T base64: {e}"),
        })
}

pub(crate) const MAX_BASEARR_LEN: usize = (1 << 21) - 1;

/// 编码符合瑞数规范的正规化 varint 长度（1~3 字节，拒绝非正规表达）
fn encode_canonical_varint(len: usize) -> Result<([u8; 3], usize), SessionError> {
    if len < 128 {
        Ok(([len as u8, 0, 0], 1))
    } else if len < 16384 {
        Ok(([0x80 | ((len >> 8) as u8), (len & 0xff) as u8, 0], 2))
    } else if len <= MAX_BASEARR_LEN {
        Ok((
            [
                0xc0 | ((len >> 16) as u8),
                ((len >> 8) & 0xff) as u8,
                (len & 0xff) as u8,
            ],
            3,
        ))
    } else {
        Err(SessionError::RuishuError {
            msg: "length exceeds supported varint capacity".to_string(),
        })
    }
}

/// 解析符合瑞数规范的正规化 varint 长度，返回 `(length, bytes_consumed)`
fn decode_canonical_varint(data: &[u8]) -> Result<(usize, usize), SessionError> {
    if data.is_empty() {
        return Err(SessionError::RuishuError {
            msg: "empty buffer for varint length".to_string(),
        });
    }
    let b0 = data[0];
    if (b0 & 0x80) == 0 {
        Ok((b0 as usize, 1))
    } else if (b0 & 0xc0) == 0x80 {
        if data.len() < 2 {
            return Err(SessionError::RuishuError {
                msg: "truncated 2-byte varint length".to_string(),
            });
        }
        let b1 = data[1];
        let len = (((b0 & 0x3f) as usize) << 8) | (b1 as usize);
        if len < 128 {
            return Err(SessionError::RuishuError {
                msg: format!("non-canonical 2-byte varint length for {len}"),
            });
        }
        Ok((len, 2))
    } else if (b0 & 0xe0) == 0xc0 {
        if data.len() < 3 {
            return Err(SessionError::RuishuError {
                msg: "truncated 3-byte varint length".to_string(),
            });
        }
        let b1 = data[1];
        let b2 = data[2];
        let len = (((b0 & 0x1f) as usize) << 16) | ((b1 as usize) << 8) | (b2 as usize);
        if len < 16384 {
            return Err(SessionError::RuishuError {
                msg: format!("non-canonical 3-byte varint length for {len}"),
            });
        }
        Ok((len, 3))
    } else {
        Err(SessionError::RuishuError {
            msg: format!("reserved or invalid varint prefix byte: 0x{b0:02x}"),
        })
    }
}

/// 构造变长明文结构
fn build_plaintext(
    keys2: &[u8; 48],
    basearr: &[u8],
    t1: u32,
    t2: u32,
) -> Result<Vec<u8>, SessionError> {
    if basearr.is_empty() || !basearr.len().is_multiple_of(16) || basearr.len() > MAX_BASEARR_LEN {
        return Err(SessionError::RuishuError {
            msg: format!(
                "invalid basearr length: expected non-empty multiple of 16 up to {MAX_BASEARR_LEN}, got {}",
                basearr.len()
            ),
        });
    }
    let (encoded_len, length_bytes) = encode_canonical_varint(basearr.len())?;
    let total_len = 15 + keys2.len() + length_bytes + basearr.len();
    let mut pt = Vec::with_capacity(total_len);
    pt.extend_from_slice(&[0, 0, 0, 0, 4, 8]);
    pt.extend_from_slice(&t1.to_be_bytes());
    pt.extend_from_slice(&t2.to_be_bytes());
    pt.push(48);
    pt.extend_from_slice(keys2);
    pt.extend_from_slice(&encoded_len[..length_bytes]);
    pt.extend_from_slice(basearr);

    let crc = crc32(&pt[4..]);
    pt[0..4].copy_from_slice(&crc.to_be_bytes());
    Ok(pt)
}

fn generate_pseudo_iv(t1: u32, t2: u32) -> [u8; 16] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(123456789);
    let mut seed = ((t1 as u64) << 32) ^ (t2 as u64) ^ ((nanos as u64) << 17);
    let mut iv = [0u8; 16];
    let (chunks, _) = iv.as_chunks_mut::<8>();
    for chunk in chunks {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let mut x = seed;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        chunk.copy_from_slice(&x.to_le_bytes());
    }
    iv
}

/// 复用已解析的会话密钥，避免自动生成路径重复解析 `cd`。
fn generate_cookie_t_with_keys(
    keys_info: &RuishuKeys,
    basearr: &[u8],
    t1: u32,
    t2: u32,
    iv: Option<[u8; 16]>,
) -> Result<String, SessionError> {
    let keys2 = keys_info.session_key()?;
    let pt = build_plaintext(keys2, basearr, t1, t2)?;

    let iv_bytes = iv.unwrap_or_else(|| generate_pseudo_iv(t1, t2));
    let (chunks, _) = iv_bytes.as_chunks::<4>();
    let iv_words = [
        u32::from_be_bytes(chunks[0]),
        u32::from_be_bytes(chunks[1]),
        u32::from_be_bytes(chunks[2]),
        u32::from_be_bytes(chunks[3]),
    ];
    let ct = encrypt_mode1(&pt, &K16, Some(iv_words))?;
    Ok(format!("a{}", encode_base64(&ct)))
}

/// 全纯算生成 Cookie T（`CtLgrmkSWHBZP`）。
///
/// 当调用方已经取得 `t1`/`t2` 和 `basearr` 时，可使用此接口；否则优先使用
/// [`generate_cookie_t_auto`]，由站点挑战自动计算这些值。
pub fn generate_cookie_t(
    cd: &str,
    basearr: &[u8],
    t1: u32,
    t2: u32,
    iv: Option<[u8; 16]>,
) -> Result<String, SessionError> {
    let keys_info = extract_keys(cd)?;
    generate_cookie_t_with_keys(&keys_info, basearr, t1, t2, iv)
}

/// 用已有 basearr 与会话挑战里的 `keys[21]` 时间戳重算 Cookie T
///
/// 时间戳取站点下发时间而非本地时钟：Tag 10 对时间敏感，服务端时间更贴近判定。
pub(crate) fn refresh_cookie_t(cd: &str, basearr: &[u8]) -> Result<String, SessionError> {
    let keys = extract_keys(cd)?;
    let t1 = keys.key_num(21)?;
    generate_cookie_t_with_keys(&keys, basearr, t1, t1 + 2, None)
}

/// LCG 线性同余 PRNG 生成 n 字节掩码
fn mask_bytes(mut seed: u32, n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        seed = ((15679u64 * ((seed & 0xffff) as u64) + 2531011) & 0xffff_ffff) as u32;
        out.extend_from_slice(&seed.to_le_bytes());
    }
    out.truncate(n);
    out
}

/// 纯算解密 Tag 6 服务端握手挑战（从 `keys[22]` 提取挑战明文）。
///
/// 当服务端未下发握手挑战（`keys[22]` 为空）时，
/// 采用标准握手前缀 `[1, 0, 1, 0, 1, 1]` 与全零挑战字段。
fn decrypt_tag6_challenge(keys22: &[u8], keys16: &[u8]) -> Result<[u8; 16], SessionError> {
    let mut tag6 = [0u8; 16];
    tag6[0] = 1;
    tag6[2] = 1;
    tag6[4] = 1;
    tag6[5] = 1;

    if keys22.is_empty() {
        return Ok(tag6);
    }

    let s = std::str::from_utf8(keys22).map_err(|e| SessionError::RuishuError {
        msg: format!("invalid keys[22] utf8: {e}"),
    })?;
    let dec22 = decode_cd(s);
    let dec_mode2 = decrypt_mode2(&dec22, keys16, true)?;
    if dec_mode2.len() < 8 {
        return Err(SessionError::RuishuError {
            msg: format!(
                "tag6 decrypted challenge too short: {} bytes",
                dec_mode2.len()
            ),
        });
    }
    tag6[6..14].copy_from_slice(&dec_mode2[..8]);
    Ok(tag6)
}

/// 客户端设备特征画像模板（Windows 10 / Chromium 默认无交互环境，40 字节）
///
/// 包含平台标识（Win32）、屏幕几何（1365x856）、页面校验标记与空交互载荷。
/// 当无指针交互时，交互载荷长度为 0（`[0x00, 0x00]`）。
pub const DEFAULT_TAG3_PROFILE: [u8; 40] = [
    0x01, 0x0a, 0x21, 0x80, // 子类型(1), 触摸点(10), eval.len(33), 128
    0x00, 0x00, 0x00, 0x00, // 初始 UA CRC32（无 UA 请求头时置 0）
    0x05, 0x57, 0x69, 0x6e, 0x33, 0x32, // 长度 5, "Win32"
    0x00, 0x00, 0x0c, 0x2f, // 耗时占位 (~3119ms)
    0x2e, 0x07, // 动态盐值占位
    0x03, 0x00, // 固定标记
    0x05, 0x55, 0x03, 0x58, 0x05, 0x55, // 几何特征 (1365, 856, 1365)
    0xdc, 0x46, 0xe8, 0xfd, // 路径 CRC32 ("/LOGIN")
    0x00, 0x00, 0x00, 0x00, // 查询参数 CRC32（无查询参数时置 0）
    0x00, 0x00, // 交互载荷长度 (0: 无鼠标/触控交互事件)
    0x00, 0x59, // 固定尾部
];

#[cfg(test)]
const SAMPLED_WIN32_TAG3_PROFILE: [u8; 52] = [
    0x01, 0x0a, 0x21, 0x80, // 子类型(1), 触摸点(10), eval.len(33), 128
    0x00, 0x00, 0x00, 0x00, // 初始 UA CRC32（无 UA 请求头时置 0）
    0x05, 0x57, 0x69, 0x6e, 0x33, 0x32, // 长度 5, "Win32"
    0x00, 0x00, 0x0c, 0x2f, // 耗时占位 (~3119ms)
    0x2e, 0x07, // 动态盐值占位
    0x03, 0x00, // 固定标记
    0x05, 0x55, 0x03, 0x58, 0x05, 0x55, // 几何特征 (1365, 856, 1365)
    0xdc, 0x46, 0xe8, 0xfd, // 路径 CRC32 ("/LOGIN")
    0x00, 0x00, 0x00, 0x00, // 查询参数 CRC32（无查询参数时置 0）
    0x00, 0x0c, // 交互载荷长度 (12)
    0x07, 0xdd, 0x14, 0x05, 0x5c, 0x56, 0x0f, 0xce, 0x9f, 0xb0, 0x27,
    0x15, // 采样交互轨迹
    0x00, 0x59, // 固定尾部
];

#[cfg(test)]
const LEGACY_MAC_TAG3_PROFILE: [u8; 55] = [
    0x01, 0x00, 0x21, 0x80, 0x9f, 0xad, 0x00, 0xee, 0x08, 0x4d, 0x61, 0x63, 0x49, 0x6e, 0x74, 0x65,
    0x6c, 0x00, 0x00, 0x08, 0xc6, 0x2f, 0x09, 0x03, 0x00, 0x04, 0x00, 0x03, 0x00, 0x04, 0x00, 0xdc,
    0x46, 0xe8, 0xfd, 0x95, 0x32, 0xfb, 0x7a, 0x00, 0x0c, 0x3b, 0xdb, 0xfc, 0x0c, 0x68, 0x79, 0x91,
    0x0f, 0xa3, 0xbc, 0x91, 0x3b, 0x00, 0x59,
];

/// 动态构建符合瑞数环境指纹规范的 Tag 3 客户端环境画像。
///
/// # 动态字段推导
/// - `user_agent`: 若提供，计算 IEEE CRC32 写入第 4..8 字节；若为 `None`，保留已有值（默认模板为 0，与原生 reqwest 空 UA 头部对齐）。
/// - `platform`: 从第 8 字节读取平台字符串长度（如 Win32 为 5，MacIntel 为 8），动态定位后续字段偏移：
///   - 运行耗时（4 字节）与随机盐值（2 字节）位于 `9 + plat_len`；
///   - 页面路径（4 字节）与查询参数 CRC32（4 字节）位于 `9 + plat_len + 14`。
/// - `page_url`: 若提供，解析路径与查询字符串并分别计算大写形式的 CRC32 写入；若为 `None`，保留已有值。
pub fn build_tag3(
    base_profile: Option<&[u8]>,
    user_agent: Option<&str>,
    page_url: Option<&str>,
) -> Result<Vec<u8>, SessionError> {
    let profile = base_profile.unwrap_or(&DEFAULT_TAG3_PROFILE);
    if profile.len() < 9 || profile.len() > u8::MAX as usize {
        return Err(SessionError::RuishuError {
            msg: format!("invalid tag3 profile length: {}", profile.len()),
        });
    }
    let plat_len = profile[8] as usize;
    let elapsed_offset = 9 + plat_len;
    if profile.len() < elapsed_offset + 26 {
        return Err(SessionError::RuishuError {
            msg: format!(
                "tag3 profile too short for platform length {plat_len}: {} bytes, need at least {}",
                profile.len(),
                elapsed_offset + 26
            ),
        });
    }
    let motion_offset = elapsed_offset + 22;
    let motion_len =
        u16::from_be_bytes([profile[motion_offset], profile[motion_offset + 1]]) as usize;
    if profile.len() != motion_offset + 2 + motion_len + 2 {
        return Err(SessionError::RuishuError {
            msg: "tag3 interaction payload length does not match profile".to_string(),
        });
    }
    let mut t3 = profile.to_vec();

    if let Some(ua) = user_agent {
        let ua_crc = crc32(ua.as_bytes());
        t3[4..8].copy_from_slice(&ua_crc.to_be_bytes());
    }

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(2246);
    let elapsed = 1500 + (nanos % 1800);
    t3[elapsed_offset..elapsed_offset + 4].copy_from_slice(&elapsed.to_be_bytes());
    t3[elapsed_offset + 4] = (nanos >> 8) as u8;
    t3[elapsed_offset + 5] = nanos as u8;

    let path_offset = elapsed_offset + 14;
    if let Some(url_str) = page_url {
        let parsed = reqwest::Url::parse(url_str).map_err(|e| SessionError::RuishuError {
            msg: format!("invalid page_url for tag3: {e}"),
        })?;
        let path = parsed.path().to_ascii_uppercase();
        let path_crc = crc32(path.as_bytes());
        t3[path_offset..path_offset + 4].copy_from_slice(&path_crc.to_be_bytes());

        let search_crc = match parsed.query() {
            Some(q) if !q.is_empty() => crc32(q.to_ascii_uppercase().as_bytes()),
            _ => 0u32,
        };
        t3[path_offset + 4..path_offset + 8].copy_from_slice(&search_crc.to_be_bytes());
    }

    Ok(t3)
}

/// 动态生成带随机耗时与 PRNG 随机盐的 Tag 3 客户端环境指纹
pub(crate) fn generate_random_tag3(base_profile: Option<&[u8]>) -> Result<Vec<u8>, SessionError> {
    build_tag3(base_profile, None, None)
}

/// 纯算组装 10 个 TLV 指纹结构并双重加密生成 innerCipher (basearr)
///
/// # 动态字段边界
/// - `code_uid` / `tag2`: 必须由 [`Coder`](coder::Coder) 算出（服务端对两者都有强校验）。
fn build_inner_cipher(
    keys_info: &RuishuKeys,
    t1: u32,
    code_uid: u16,
    tag2: [u8; 4],
    tag3_profile: Option<&[u8]>,
) -> Result<Vec<u8>, SessionError> {
    let keys2 = keys_info.session_key()?;
    let seed: u32 = keys_info.key_num(47)?;
    let counter: u32 = keys_info.key_num(19)?;
    let tag6 = decrypt_tag6_challenge(keys_info.key(22)?, keys_info.site_key()?)?;
    let tag3 = generate_random_tag3(tag3_profile)?;

    let mut tag10 = [0u8; 18];
    tag10[1] = 2;
    tag10[2..6].copy_from_slice(&t1.to_be_bytes());
    tag10[6..10].copy_from_slice(&counter.to_be_bytes());
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(1337);
    let hi = (nanos % 1048575).to_be_bytes();
    let lo = (t1.wrapping_mul(1000).wrapping_add(1337)).to_be_bytes();
    tag10[10..14].copy_from_slice(&hi);
    tag10[14..18].copy_from_slice(&lo);

    let mut tag7 = [0u8; 8];
    tag7[4] = 0x14;
    tag7[5] = 0x16;
    tag7[6..8].copy_from_slice(&code_uid.to_be_bytes());

    let tlvs: [(u8, &[u8]); 10] = [
        (3, &tag3),
        (10, &tag10),
        (7, &tag7),
        (0, &[0]),
        (6, &tag6),
        (
            4,
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc0, 0xff, 0xff, 0x02],
        ),
        (16, &[4, 16, 0, 0, 0, 0, 5, 44, 44, 44, 44, 44]),
        (2, &tag2),
        (9, &[8, 0]),
        (13, &[0]),
    ];

    let mut tlv_bytes = Vec::with_capacity(tlvs.iter().map(|(_, value)| 2 + value.len()).sum());
    for (tag, val) in tlvs {
        let sub_mask = mask_bytes(seed.wrapping_add(tag as u32).wrapping_add(1), val.len());
        tlv_bytes.push(tag);
        tlv_bytes.push(val.len() as u8);
        tlv_bytes.extend(val.iter().zip(&sub_mask).map(|(a, b)| a ^ b));
    }

    let outer_mask = mask_bytes(seed, tlv_bytes.len());
    for (byte, mask) in tlv_bytes.iter_mut().zip(&outer_mask) {
        *byte ^= mask;
    }
    for (a, b) in tlv_bytes.iter_mut().zip(&keys2[..16]) {
        *a ^= b;
    }

    encrypt_mode1(&tlv_bytes, keys_info.key(17)?, None)
}
/// 基于会话 `cd` 与站点 `mainjs` 纯算 Cookie T（时间戳由调用方给定）
///
/// `code_uid`（Tag 7）与 `tag2` 由本接口从 `mainjs` 与 `nsd` 内部算出。
pub fn generate_cookie_t_pure(
    cd: &str,
    mainjs: &str,
    nsd: u32,
    t1: u32,
    t2: u32,
    tag3_profile: Option<&[u8]>,
    iv: Option<[u8; 16]>,
) -> Result<String, SessionError> {
    let keys_info = extract_keys(cd)?;
    keys_info.session_key()?;
    let mut coder = coder::Coder::new(nsd, mainjs);
    coder.run();
    let code_uid = coder.code_uid(&keys_info)?;
    let tag2 = coder.tag2(&keys_info)?;
    let basearr = build_inner_cipher(&keys_info, t1, code_uid, tag2, tag3_profile)?;
    generate_cookie_t_with_keys(&keys_info, &basearr, t1, t2, iv)
}

/// Cookie T 解密明文结构
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedCookieT {
    /// 头部解出的 CRC32 值
    pub crc: u32,
    /// CRC 自校验是否通过
    pub crc_valid: bool,
    /// 协议版本标识 (固定 4)
    pub version: u8,
    /// 起始秒级时间戳 t1
    pub t1: u32,
    /// 运行秒级时间戳 t2
    pub t2: u32,
    /// 会话密钥 `keys[2]` (48 字节)
    pub keys2: Vec<u8>,
    /// 客户端环境特征密文数组 (AES 块大小 16 的正整数倍)
    pub basearr: Vec<u8>,
    /// 完整解密原始明文
    pub raw_plaintext: Vec<u8>,
}

/// 校验并解密 Cookie T 字符串。
///
/// 解密结果中的 [`DecryptedCookieT::basearr`] 可交给
/// [`crate::session::Session::set_basearr`]，用于后续 `412` 自动重算。
///
/// ```no_run
/// # use rsmycqu::session::ruishu::decrypt_cookie_t;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let decoded = decrypt_cookie_t("浏览器复制的 Cookie T")?;
/// assert!(decoded.crc_valid);
/// # Ok(())
/// # }
/// ```
pub fn decrypt_cookie_t(cookie: &str) -> Result<DecryptedCookieT, SessionError> {
    let ct_bytes = decode_base64(cookie)?;
    let pt = decrypt_mode2(&ct_bytes, &K16, true)?;
    if pt.len() < 63 + 1 + 16 {
        return Err(SessionError::RuishuError {
            msg: format!("decrypted plaintext too short: {} bytes", pt.len()),
        });
    }

    let crc = u32::from_be_bytes([pt[0], pt[1], pt[2], pt[3]]);
    let calc_crc = crc32(&pt[4..]);
    if crc != calc_crc {
        return Err(SessionError::RuishuError {
            msg: format!("CRC32 checksum mismatch: expected 0x{calc_crc:08x}, got 0x{crc:08x}"),
        });
    }
    let crc_valid = true;

    let version = pt[4];
    if version != 4 {
        return Err(SessionError::RuishuError {
            msg: format!("unsupported protocol version: expected 4, got {version}"),
        });
    }

    let ts_len = pt[5];
    if ts_len != 8 {
        return Err(SessionError::RuishuError {
            msg: format!("invalid timestamp block length: expected 8, got {ts_len}"),
        });
    }

    let t1 = u32::from_be_bytes([pt[6], pt[7], pt[8], pt[9]]);
    let t2 = u32::from_be_bytes([pt[10], pt[11], pt[12], pt[13]]);

    let k2_len = pt[14] as usize;
    if k2_len != 48 {
        return Err(SessionError::RuishuError {
            msg: format!("invalid keys2 length: expected 48, got {k2_len}"),
        });
    }
    let keys2 = pt[15..63].to_vec();

    let (ba_len, varint_len) = decode_canonical_varint(&pt[63..])?;
    if ba_len == 0 || !ba_len.is_multiple_of(16) || ba_len > MAX_BASEARR_LEN {
        return Err(SessionError::RuishuError {
            msg: format!(
                "invalid basearr length in plaintext: expected non-empty multiple of 16 up to {MAX_BASEARR_LEN}, got {ba_len}"
            ),
        });
    }

    let expected_total_len = 63 + varint_len + ba_len;
    if pt.len() < expected_total_len {
        return Err(SessionError::RuishuError {
            msg: format!(
                "truncated basearr in plaintext: expected {expected_total_len} bytes, got {}",
                pt.len()
            ),
        });
    }
    if pt.len() > expected_total_len {
        return Err(SessionError::RuishuError {
            msg: format!(
                "extraneous trailing bytes in plaintext: expected {expected_total_len} bytes, got {}",
                pt.len()
            ),
        });
    }

    let basearr = pt[63 + varint_len..expected_total_len].to_vec();

    Ok(DecryptedCookieT {
        crc,
        crc_valid,
        version,
        t1,
        t2,
        keys2,
        basearr,
        raw_plaintext: pt,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(serde::Deserialize)]
    struct FixtureSession {
        cd: String,
        cookie_t: String,
        keys_16_hex: String,
        keys_2_hex: String,
    }

    #[derive(serde::Deserialize)]
    struct FixtureData {
        session_1: FixtureSession,
        session_2: FixtureSession,
        session_3: FixtureSession,
    }

    fn fixture() -> FixtureData {
        serde_json::from_str(include_str!("../../../tests/fixtures/ruishu_sessions.json")).unwrap()
    }
    #[test]
    fn test_cfgnum_sbox() {
        let (arr1, arr2) = make_cfgnum();
        assert_eq!(arr1[4][0], 99);
        assert_eq!(arr1[4][1], 124);
        assert_eq!(arr2[4][99], 0);
        assert_eq!(arr2[4][124], 1);
    }

    #[test]
    fn test_crc32() {
        let data = b"123456789";
        assert_eq!(crc32(data), 0xcbf4_3926);
    }

    #[test]
    fn test_extract_keys_all_sessions() {
        let f = fixture();
        for (name, s) in [
            ("session_1", &f.session_1),
            ("session_2", &f.session_2),
            ("session_3", &f.session_3),
        ] {
            let k = extract_keys(&s.cd).unwrap_or_else(|e| panic!("failed for {name}: {e:?}"));
            assert_eq!(
                hex::encode(k.site_key().unwrap()),
                s.keys_16_hex,
                "site key mismatch for {name}"
            );
            assert_eq!(
                hex::encode(k.session_key().unwrap()),
                s.keys_2_hex,
                "session key mismatch for {name}"
            );
        }
    }

    #[test]
    fn test_decrypt_real_cookies_all_sessions() {
        let f = fixture();
        for (name, s) in [
            ("session_1", &f.session_1),
            ("session_2", &f.session_2),
            ("session_3", &f.session_3),
        ] {
            let dec = decrypt_cookie_t(&s.cookie_t)
                .unwrap_or_else(|e| panic!("failed for {name}: {e:?}"));
            assert!(dec.crc_valid, "crc invalid for {name}");
            assert_eq!(dec.version, 4, "version != 4 for {name}");
            assert_eq!(
                hex::encode(&dec.keys2),
                s.keys_2_hex,
                "keys2 mismatch for {name}"
            );
            assert_eq!(dec.basearr.len(), 160, "basearr len != 160 for {name}");
        }
    }

    #[test]
    fn test_generate_cookie_t_roundtrip() {
        let f = fixture();
        let s = &f.session_1;
        let dec = decrypt_cookie_t(&s.cookie_t).unwrap();
        let iv = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let generated_cookie =
            generate_cookie_t(&s.cd, &dec.basearr, dec.t1, dec.t2, Some(iv)).unwrap();

        assert_eq!(generated_cookie.len(), 343);
        assert!(generated_cookie.starts_with('a'));

        let re_dec =
            decrypt_cookie_t(&generated_cookie).expect("failed to decrypt generated cookie");
        assert!(re_dec.crc_valid);
        assert_eq!(re_dec.version, 4);
        assert_eq!(re_dec.t1, dec.t1);
        assert_eq!(re_dec.t2, dec.t2);
        assert_eq!(re_dec.keys2, dec.keys2);
        assert_eq!(re_dec.basearr, dec.basearr);
    }
    /// 自动纯算链路：页面 + mainjs → Cookie T，其中的 Tag 7 必须等于参考值
    #[test]
    #[ignore = "requires external mainjs script specified via RSMYCQU_MAINJS"]
    fn generate_cookie_t_auto_embeds_reference_code_uid() {
        let path = std::env::var("RSMYCQU_MAINJS")
            .expect("RSMYCQU_MAINJS environment variable must be set to mainjs.js path");
        let mainjs = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read RSMYCQU_MAINJS from {path}: {e}"));
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/ruishu_coder.json"))
                .unwrap();

        for name in ["session_1", "session_2", "session_3", "session_4"] {
            let v = &vectors["vectors"][name];
            let nsd = v["nsd"].as_u64().unwrap() as u32;
            let cd = v["cd"].as_str().unwrap();
            let expected = v["code_uid"].as_u64().unwrap() as u16;

            let (cookie_t, basearr) = generate_cookie_t_auto(&mainjs, nsd, cd).unwrap();

            let dec = decrypt_cookie_t(&cookie_t).unwrap();
            assert!(dec.crc_valid, "{name}");
            assert_eq!(dec.basearr, basearr, "{name}");

            let keys = extract_keys(cd).unwrap();
            let tag7 = tlv_value(&dec, &keys, 7);
            assert_eq!(
                ((tag7[6] as u16) << 8) | tag7[7] as u16,
                expected,
                "Tag 7 code_uid {name}"
            );
            // Tag 6 由 keys[22] 纯算而来，组装结果必须与之逐字节一致
            let expected_tag6 =
                decrypt_tag6_challenge(keys.key(22).unwrap(), keys.site_key().unwrap()).unwrap();
            assert_eq!(
                tlv_value(&dec, &keys, 6),
                expected_tag6.to_vec(),
                "Tag 6 assembly {name}"
            );
        }
    }

    /// 解开内层 TLV 取指定 tag 的明文值
    fn tlv_value(dec: &DecryptedCookieT, keys: &RuishuKeys, want: u8) -> Vec<u8> {
        let mut x = decrypt_mode2(&dec.basearr, keys.key(17).unwrap(), false).unwrap();
        for (a, b) in x.iter_mut().zip(&dec.keys2[..16]) {
            *a ^= b;
        }
        let seed = keys.key_num(47).unwrap();
        let raw: Vec<u8> = x
            .iter()
            .zip(&mask_bytes(seed, x.len()))
            .map(|(a, b)| a ^ b)
            .collect();
        let mut pos = 0;
        while pos + 1 < raw.len() {
            let tag = raw[pos];
            let len = raw[pos + 1] as usize;
            if pos + 2 + len > raw.len() {
                break;
            }
            if tag == want {
                return raw[pos + 2..pos + 2 + len]
                    .iter()
                    .zip(&mask_bytes(seed.wrapping_add(u32::from(want) + 1), len))
                    .map(|(a, b)| a ^ b)
                    .collect();
            }
            pos += 2 + len;
        }
        panic!("Tag {want} not found in inner TLV");
    }

    #[test]
    fn test_decrypt_tag6_challenge_all_sessions() {
        let f = fixture();
        for (name, s, expected_token_hex) in [
            ("session_1", &f.session_1, "5513a3e7266a0100"),
            ("session_2", &f.session_2, "a816a3e7266a0100"),
            ("session_3", &f.session_3, "4219a3e7266a0100"),
        ] {
            let k = extract_keys(&s.cd).unwrap();
            let tag6 = decrypt_tag6_challenge(k.key(22).unwrap(), k.site_key().unwrap()).unwrap();
            assert_eq!(
                hex::encode(&tag6[6..14]),
                expected_token_hex,
                "tag6 mismatch for {name}"
            );
        }
    }

    #[rstest::rstest]
    fn test_decrypt_tag6_challenge_empty_keys22() {
        let tag6 = decrypt_tag6_challenge(&[], &[0u8; 16]).unwrap();
        assert_eq!(tag6, [1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[rstest::rstest]
    fn test_build_tag3_ua_and_url_injection() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        let url = "https://sso.cqu.edu.cn/login?service=https%3A%2F%2Fmy.cqu.edu.cn%2Fauthserver%2Fauthentication%2Fcas";
        let t3 = build_tag3(None, Some(ua), Some(url)).unwrap();
        assert_eq!(t3.len(), 40);
        assert_eq!(&t3[4..8], &crc32(ua.as_bytes()).to_be_bytes());
        assert_eq!(&t3[28..32], &crc32(b"/LOGIN").to_be_bytes());
        let expected_search_crc =
            crc32(b"SERVICE=HTTPS%3A%2F%2FMY.CQU.EDU.CN%2FAUTHSERVER%2FAUTHENTICATION%2FCAS");
        assert_eq!(&t3[32..36], &expected_search_crc.to_be_bytes());
        assert_eq!(&t3[36..38], &[0, 0]);
        assert_eq!(&t3[38..40], &[0, 0x59]);
    }

    #[rstest::rstest]
    #[case::windows(&DEFAULT_TAG3_PROFILE)]
    #[case::sampled_win52(&SAMPLED_WIN32_TAG3_PROFILE)]
    #[case::mac(&LEGACY_MAC_TAG3_PROFILE)]
    fn test_tag3_randomization_preserves_other_profile_fields(#[case] profile: &[u8]) {
        let t3 = build_tag3(Some(profile), None, None).unwrap();
        let elapsed_offset = 9 + usize::from(profile[8]);
        let elapsed =
            u32::from_be_bytes(t3[elapsed_offset..elapsed_offset + 4].try_into().unwrap());
        assert!((1500..3300).contains(&elapsed));
        assert_eq!(&t3[..elapsed_offset], &profile[..elapsed_offset]);
        assert_eq!(&t3[elapsed_offset + 6..], &profile[elapsed_offset + 6..]);
    }

    #[rstest::rstest]
    #[case::empty(vec![])]
    #[case::missing_platform_length(vec![0; 8])]
    #[case::platform_overrun(vec![255; 52])]
    #[case::oversized(vec![0; 256])]
    #[case::truncated_motion(DEFAULT_TAG3_PROFILE[..39].to_vec())]
    #[case::inconsistent_motion({
        let mut profile = DEFAULT_TAG3_PROFILE.to_vec();
        profile[37] = 1;
        profile
    })]
    fn test_tag3_rejects_malformed_profiles(#[case] profile: Vec<u8>) {
        assert!(matches!(
            build_tag3(Some(&profile), None, None),
            Err(SessionError::RuishuError { .. })
        ));
    }

    #[rstest::rstest]
    fn test_tag3_rejects_invalid_page_url() {
        assert!(matches!(
            build_tag3(None, None, Some("not a URL")),
            Err(SessionError::RuishuError { .. })
        ));
    }

    #[test]
    fn test_decrypt_mode2_rejects_malformed_input_and_bad_pkcs7() {
        let key = [0x42u8; 16];
        assert!(decrypt_mode2(&[0u8; 15], &key, false).is_err());
        assert!(decrypt_mode2(&[0u8; 17], &key, false).is_err());
        assert!(decrypt_mode2(&[0u8; 31], &key, true).is_err());
        assert!(decrypt_mode2(&[], &key, false).is_err());

        let ct = encrypt_mode1(b"boundary test", &key, None).unwrap();
        assert_eq!(ct.len(), 16);
        assert_eq!(decrypt_mode2(&ct, &key, false).unwrap(), b"boundary test");

        let mut bad_ct = encrypt_mode1(b"boundary test", &key, Some([0u32; 4])).unwrap();
        // 修改 IV 只破坏倒数第二个填充字节，末尾填充长度仍为 3。
        bad_ct[14] ^= 0x01;
        assert!(decrypt_mode2(&bad_ct, &key, true).is_err());
    }

    #[test]
    fn test_decrypt_cookie_t_rejects_truncated_plaintext_lengths() {
        let mut pt = vec![0u8; 80];
        pt[4] = 4;
        pt[14] = 65;
        let iv_words = [1u32, 2, 3, 4];
        let ct = encrypt_mode1(&pt, &K16, Some(iv_words)).unwrap();
        let cookie = format!("a{}", encode_base64(&ct));

        let result = decrypt_cookie_t(&cookie);
        assert!(result.is_err());
    }

    fn encode_cd(raw: &[u8]) -> String {
        let mut out = String::with_capacity(raw.len().div_ceil(3) * 4);
        for chunk in raw.chunks(3) {
            let b0 = chunk[0] as usize;
            let b1 = *chunk.get(1).unwrap_or(&0) as usize;
            let b2 = *chunk.get(2).unwrap_or(&0) as usize;
            out.push(BASESTR[b0 >> 2] as char);
            out.push(BASESTR[((b0 & 3) << 4) | (b1 >> 4)] as char);
            if chunk.len() >= 2 {
                out.push(BASESTR[((b1 & 15) << 2) | (b2 >> 6)] as char);
            }
            if chunk.len() >= 3 {
                out.push(BASESTR[b2 & 63] as char);
            }
        }
        out
    }

    // 保留其余真实密钥，只替换会话密钥及对应长度。
    fn make_challenge_with_session_key(keys: &[Vec<u8>], malformed_session_key: &[u8]) -> String {
        let mut ans = Vec::from(&MASK[..]);
        let k0 = &keys[0];
        let mut k0_padded = k0.clone();
        if k0_padded.len() < 566 {
            k0_padded.resize(566, 0);
        }
        ans.extend_from_slice(&k0_padded[5..]);
        let k1 = &keys[1];
        ans.extend_from_slice(&(k1.len() as u16).to_be_bytes());
        ans.extend_from_slice(k1);
        ans.extend_from_slice(&(malformed_session_key.len() as u16).to_be_bytes());
        ans.extend_from_slice(malformed_session_key);
        for k in &keys[3..] {
            ans.extend_from_slice(&(k.len() as u16).to_be_bytes());
            ans.extend_from_slice(k);
        }
        let mut s = vec![0u8; ans.len()];
        for i in 8..ans.len() {
            s[i] = ans[i] ^ MASK[i % 8];
        }
        let mut a = vec![0u8, 0];
        a.extend_from_slice(&s);
        while a.len() % 3 != 0 {
            a.push(0);
        }
        encode_cd(&a)
    }

    #[rstest::rstest]
    #[case(0)]
    #[case(8)]
    #[case(16)]
    #[case(47)]
    #[case(49)]
    fn malformed_session_key_returns_error(#[case] len: usize) {
        let fixture = fixture();
        let session = &fixture.session_1;
        let decoded = decrypt_cookie_t(&session.cookie_t).unwrap();
        let valid_keys = extract_keys(&session.cd).unwrap();
        let cd = make_challenge_with_session_key(&valid_keys.keys, &vec![0x42; len]);
        let keys = extract_keys(&cd).unwrap();
        assert!(matches!(
            build_inner_cipher(&keys, decoded.t1, 0x1234, [0, 1, 2, 3], None),
            Err(SessionError::RuishuError { .. })
        ));
        assert!(matches!(
            generate_cookie_t(&cd, &decoded.basearr, decoded.t1, decoded.t2, None),
            Err(SessionError::RuishuError { .. })
        ));
        assert!(matches!(
            refresh_cookie_t(&cd, &decoded.basearr),
            Err(SessionError::RuishuError { .. })
        ));
        assert!(matches!(
            generate_cookie_t_auto("", 107802, &cd),
            Err(SessionError::RuishuError { .. })
        ));
        assert!(matches!(
            generate_cookie_t_pure(&cd, "", 107802, decoded.t1, decoded.t2, None, None),
            Err(SessionError::RuishuError { .. })
        ));
    }
    #[rstest::rstest]
    fn test_canonical_varint_roundtrip() {
        for len in [
            1usize, 16, 127, 128, 160, 288, 1024, 4096, 16383, 16384, 65536,
        ] {
            let (encoded, size) = encode_canonical_varint(len).unwrap();
            let (decoded_len, consumed) = decode_canonical_varint(&encoded[..size]).unwrap();
            assert_eq!(decoded_len, len);
            assert_eq!(consumed, size);
        }
    }

    #[rstest::rstest]
    fn test_canonical_varint_rejects_non_canonical_and_reserved() {
        assert!(decode_canonical_varint(&[0x80, 0x10]).is_err());
        assert!(decode_canonical_varint(&[0xc0, 0x00, 0x80]).is_err());
        assert!(decode_canonical_varint(&[0xe0, 0x01]).is_err());
        assert!(decode_canonical_varint(&[0xff]).is_err());
        assert!(decode_canonical_varint(&[]).is_err());
    }

    #[rstest::rstest]
    fn test_build_plaintext_and_decrypt_cookie_t_roundtrip_288() {
        let f = fixture();
        let s = &f.session_1;
        let keys_info = extract_keys(&s.cd).unwrap();
        let fake_288_basearr = vec![0x37u8; 288];
        let t1 = 1700000000u32;
        let t2 = t1 + 2;
        let iv = [9u8; 16];
        let cookie = generate_cookie_t(&s.cd, &fake_288_basearr, t1, t2, Some(iv)).unwrap();
        let dec = decrypt_cookie_t(&cookie).unwrap();
        assert!(dec.crc_valid);
        assert_eq!(dec.version, 4);
        assert_eq!(dec.t1, t1);
        assert_eq!(dec.t2, t2);
        assert_eq!(dec.keys2, keys_info.session_key().unwrap());
        assert_eq!(dec.basearr, fake_288_basearr);
    }

    #[rstest::rstest]
    fn test_decrypt_cookie_t_rejects_corrupted_crc() {
        let f = fixture();
        let s = &f.session_1;
        let dec = decrypt_cookie_t(&s.cookie_t).unwrap();
        let mut pt = dec.raw_plaintext.clone();
        pt[0] ^= 0xff;
        let iv_words = [1u32, 2, 3, 4];
        let ct = encrypt_mode1(&pt, &K16, Some(iv_words)).unwrap();
        let cookie = format!("a{}", encode_base64(&ct));
        assert!(matches!(
            decrypt_cookie_t(&cookie),
            Err(SessionError::RuishuError { .. })
        ));
    }

    #[rstest::rstest]
    fn test_decrypt_cookie_t_rejects_invalid_version() {
        let f = fixture();
        let s = &f.session_1;
        let dec = decrypt_cookie_t(&s.cookie_t).unwrap();
        let mut pt = dec.raw_plaintext.clone();
        pt[4] = 5;
        let crc = crc32(&pt[4..]);
        pt[0..4].copy_from_slice(&crc.to_be_bytes());
        let iv_words = [1u32, 2, 3, 4];
        let ct = encrypt_mode1(&pt, &K16, Some(iv_words)).unwrap();
        let cookie = format!("a{}", encode_base64(&ct));
        assert!(matches!(
            decrypt_cookie_t(&cookie),
            Err(SessionError::RuishuError { .. })
        ));
    }

    #[rstest::rstest]
    fn test_decrypt_cookie_t_rejects_invalid_ts_len() {
        let f = fixture();
        let s = &f.session_1;
        let dec = decrypt_cookie_t(&s.cookie_t).unwrap();
        let mut pt = dec.raw_plaintext.clone();
        pt[5] = 9;
        let crc = crc32(&pt[4..]);
        pt[0..4].copy_from_slice(&crc.to_be_bytes());
        let iv_words = [1u32, 2, 3, 4];
        let ct = encrypt_mode1(&pt, &K16, Some(iv_words)).unwrap();
        let cookie = format!("a{}", encode_base64(&ct));
        assert!(matches!(
            decrypt_cookie_t(&cookie),
            Err(SessionError::RuishuError { .. })
        ));
    }

    #[rstest::rstest]
    fn test_decrypt_cookie_t_rejects_invalid_keys2_len() {
        let f = fixture();
        let s = &f.session_1;
        let dec = decrypt_cookie_t(&s.cookie_t).unwrap();
        let mut pt = dec.raw_plaintext.clone();
        pt[14] = 47;
        let crc = crc32(&pt[4..]);
        pt[0..4].copy_from_slice(&crc.to_be_bytes());
        let iv_words = [1u32, 2, 3, 4];
        let ct = encrypt_mode1(&pt, &K16, Some(iv_words)).unwrap();
        let cookie = format!("a{}", encode_base64(&ct));
        assert!(matches!(
            decrypt_cookie_t(&cookie),
            Err(SessionError::RuishuError { .. })
        ));
    }

    #[rstest::rstest]
    fn test_decrypt_cookie_t_rejects_trailing_extra_bytes() {
        let f = fixture();
        let s = &f.session_1;
        let dec = decrypt_cookie_t(&s.cookie_t).unwrap();
        let mut pt = dec.raw_plaintext.clone();
        pt.push(0x5a);
        let crc = crc32(&pt[4..]);
        pt[0..4].copy_from_slice(&crc.to_be_bytes());
        let iv_words = [1u32, 2, 3, 4];
        let ct = encrypt_mode1(&pt, &K16, Some(iv_words)).unwrap();
        let cookie = format!("a{}", encode_base64(&ct));
        assert!(matches!(
            decrypt_cookie_t(&cookie),
            Err(SessionError::RuishuError { .. })
        ));
    }

    #[rstest::rstest]
    fn test_build_plaintext_rejects_invalid_basearr_lengths() {
        let keys2 = [0x11u8; 48];
        assert!(build_plaintext(&keys2, &[], 100, 102).is_err());
        assert!(build_plaintext(&keys2, &[0u8; 15], 100, 102).is_err());
        assert!(build_plaintext(&keys2, &[0u8; 17], 100, 102).is_err());
        assert!(build_plaintext(&keys2, &vec![0u8; MAX_BASEARR_LEN + 1], 100, 102).is_err());
        assert!(build_plaintext(&keys2, &[0u8; 160], 100, 102).is_ok());
        assert!(build_plaintext(&keys2, &[0u8; 288], 100, 102).is_ok());
    }
}
