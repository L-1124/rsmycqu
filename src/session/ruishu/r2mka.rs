//! r2mka 任务表解析与 Tag 2（`fixedValue20`）取值
//!
//! 站点把任务表编码在 mainjs 的 globalText1 里，Tag 2 的 4 字节取自一张 20 项的常量表：
//! 先按任务表里每 7 项一组的第 7 个下标，把「keyname → 常量」记进映射，
//! 再用本会话 `keys[29..32]` 对应的 keyname 去取。

use crate::errors::session::SessionError;
/// 20 项常量表（站点侧硬编码）
const VALUES: [u8; 20] = [
    103, 0, 102, 203, 224, 181, 108, 240, 101, 126, 103, 11, 102, 203, 225, 181, 208, 180, 100, 127,
];

/// Tag 2 目标节点的 uid（站点固定）
const TARGET_UID: &str = "U250200532";

/// 任务表游标：长度前缀式读取（`getLine` 以首字节为长度，0 表示空）
struct Cursor<'a> {
    chars: &'a [char],
    pos: usize,
}

impl Cursor<'_> {
    fn code(&mut self) -> u32 {
        let c = self.chars.get(self.pos).copied().unwrap_or('\0');
        self.pos += 1;
        c as u32
    }

    fn line(&mut self) -> String {
        let n = self.code() as usize;
        if n == 0 {
            return String::new();
        }
        let end = (self.pos + n).min(self.chars.len());
        let s: String = self.chars[self.pos.min(end)..end].iter().collect();
        self.pos += n;
        s
    }

    /// `getList`：按 0xFF 切分的行
    fn list(&mut self) {
        let _ = self.line();
    }
}

/// 站点 uid 编码：六元组 → 两字符一组按十六进制取字符码 → 十进制拼接
fn uid_of(
    deep: usize,
    lens: usize,
    is_reset: usize,
    task_len: usize,
    c1: usize,
    c2: usize,
) -> String {
    let spec = format!("{deep}-{lens}-{is_reset}-{task_len}-{c1}-{c2}");
    let bytes = spec.as_bytes();
    let mut uid = String::from("U");
    for chunk in bytes.chunks(2) {
        uid.push_str(&js_char_code(chunk).to_string());
    }
    uid
}

/// 等价于 JS `String.fromCharCode(parseInt(chunk, 16)).charCodeAt(0)`：
/// 允许前导正负号，非法处即停，全非法为 0，最终取低 16 位
fn js_char_code(chunk: &[u8]) -> u32 {
    let mut idx = 0;
    let mut sign: i64 = 1;
    match chunk.first() {
        Some(b'-') => {
            sign = -1;
            idx = 1;
        }
        Some(b'+') => idx = 1,
        _ => {}
    }
    let mut value: i64 = 0;
    let mut digits = 0;
    while idx < chunk.len() {
        match (chunk[idx] as char).to_digit(16) {
            Some(d) => {
                value = value * 16 + i64::from(d);
                digits += 1;
                idx += 1;
            }
            None => break,
        }
    }
    if digits == 0 {
        return 0;
    }
    (sign * value).rem_euclid(65536) as u32
}

/// 深度优先遍历任务表，收集 uid 命中的节点的 `taskori`
fn walk(cur: &mut Cursor, depth: usize, found: &mut Vec<Vec<u32>>) {
    let lens = cur.code() as usize;
    let is_reset = cur.code() as usize;
    let task_len = cur.code() as usize;
    let task_start = cur.pos;
    cur.pos += task_len;

    let child_one = cur.code() as usize;
    for _ in 0..child_one {
        walk(cur, depth + 1, found);
    }
    let child_two = cur.code() as usize;
    for _ in 0..child_two {
        walk(cur, depth + 1, found);
    }

    if uid_of(depth, lens, is_reset, task_len, child_one + 2, child_two) == TARGET_UID {
        let end = (task_start + task_len).min(cur.chars.len());
        found.push(
            cur.chars[task_start..end]
                .iter()
                .map(|&c| c as u32)
                .collect(),
        );
    }
}

/// 由 keyname 表与任务表算出 Tag 2 的 4 字节
pub(crate) fn tag2(
    task_text: &str,
    keynames: &[String],
    keys: &super::RuishuKeys,
) -> Result<[u8; 4], SessionError> {
    let chars: Vec<char> = task_text.chars().collect();
    let mut cur = Cursor {
        chars: &chars,
        pos: 6,
    };
    // 站点顺序：先跳过两条列表与两个配置下标，再读任务树
    cur.list();
    cur.list();
    cur.code();
    cur.code();
    let mut found = Vec::new();
    walk(&mut cur, 0, &mut found);

    if found.is_empty() {
        return Err(SessionError::RuishuError {
            msg: format!("r2mka task {TARGET_UID} not found"),
        });
    }

    for taskori in found {
        let mut out = [0u8; 4];
        let mut complete = true;
        for (slot, key_idx) in out.iter_mut().zip([29usize, 30, 31, 32]) {
            let target = std::str::from_utf8(keys.key(key_idx)?).unwrap_or_default();
            let mut val = None;
            for (idx, &v) in VALUES.iter().enumerate() {
                if let Some(name) = taskori
                    .get(idx * 7 + 6)
                    .and_then(|c| keynames.get(*c as usize))
                    && name.as_str() == target
                {
                    val = Some(v);
                    break;
                }
            }
            match val {
                Some(v) => *slot = v,
                None => {
                    complete = false;
                    break;
                }
            }
        }
        if complete {
            return Ok(out);
        }
    }

    Err(SessionError::RuishuError {
        msg: "r2mka task did not yield 4 tag2 bytes".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_matches_site_encoding() {
        // 实测节点：deep=2, lens=5, isReset=0, taskori=140, child_one=3(+2), child_two=20
        assert_eq!(uid_of(2, 5, 0, 140, 5, 20), "U250200532");
        assert_eq!(uid_of(0, 0, 0, 0, 0, 0), "U000000");
        // "-1" 走 JS 的 fromCharCode(-1) → 65535
        assert_eq!(uid_of(10, 16, 1, 1, 1, 1), "U166553561111");
    }

    #[test]
    fn cursor_reads_length_prefixed_values() {
        // 长度前缀：code=2, line=("ab"), 再一个 code
        let text: Vec<char> = "\u{2}\u{2}ab\u{7}".chars().collect();
        let mut cur = Cursor {
            chars: &text,
            pos: 0,
        };
        assert_eq!(cur.code(), 2);
        assert_eq!(cur.line(), "ab");
        assert_eq!(cur.code(), 7);
        assert_eq!(cur.line(), "");
    }
}
