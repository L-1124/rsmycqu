//! 站点外层脚本（mainjs）解包器：重建可读代码并复算 Tag 7 的 16 位校验和 `code_uid`
//!
//! 站点在页面里下发混淆脚本，客户端执行后从当前会话 `keys[33]`/`keys[34]` 指定的函数与代码切片上
//! 算出一个 16 位校验和写进 Tag 7；服务端逐位校验（翻一位即 HTTP 400）。本模块按站点脚本的原始流程
//! 重建那份代码，因此除 `mainjs` 源码与 `$_ts.nsd` 之外不依赖任何运行时。

use std::{fmt::Write, sync::LazyLock};

use regex::Regex;

use crate::errors::session::SessionError;

/// 站点 PRNG（mainjs `_$ad`）：每次取低 16 位做线性同余
struct Scd(u32);

impl Scd {
    fn new(seed: u32) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u32 {
        self.0 = 15679u32.wrapping_mul(self.0 & 0xFFFF).wrapping_add(2531011);
        self.0
    }
}

/// Fisher-Yates 洗牌（mainjs `_$lT`）：原地洗牌
fn array_shuffle<T>(arr: &mut [T], scd: &mut Scd) {
    let mut len = arr.len();
    while len > 1 {
        len -= 1;
        let i = scd.next() as usize % len;
        arr.swap(len, i);
    }
}

/// 变量名生成（mainjs op 53+21+46）：`_$` 加双字符，按 `nsd` 洗牌
fn gren_keys(num: usize, nsd: u32) -> Vec<String> {
    const CHARS: &str = "_$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let chars: Vec<char> = CHARS.chars().collect();
    let mut names = Vec::with_capacity(num);
    for &c0 in &chars {
        for &c1 in &chars {
            if names.len() >= num {
                break;
            }
            names.push(format!("_${c0}{c1}"));
        }
    }
    array_shuffle(&mut names, &mut Scd::new(nsd));
    names
}

/// 按 JS 字符串字面量语义还原转义
fn unescape_js(raw: &str) -> String {
    if raw.contains('\n') || raw.contains('\r') {
        return raw.to_string();
    }
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let Some(escaped) = chars.next() else {
            out.push('\\');
            break;
        };
        match escaped {
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            'b' => out.push('\u{8}'),
            'f' => out.push('\u{c}'),
            'v' => out.push('\u{b}'),
            '0' => out.push('\0'),
            'x' => {
                let mut val = 0u32;
                let mut valid = true;
                let mut buf = ['\0'; 2];
                for slot in &mut buf {
                    if let Some(ch) = chars.next() {
                        *slot = ch;
                        if let Some(d) = ch.to_digit(16) {
                            val = (val << 4) | d;
                        } else {
                            valid = false;
                            break;
                        }
                    } else {
                        valid = false;
                        break;
                    }
                }
                if valid && let Some(ch) = char::from_u32(val) {
                    out.push(ch);
                } else {
                    out.push('x');
                    for &ch in &buf {
                        if ch != '\0' {
                            out.push(ch);
                        }
                    }
                }
            }
            'u' => {
                let mut val = 0u32;
                let mut valid = true;
                let mut buf = ['\0'; 4];
                for slot in &mut buf {
                    if let Some(ch) = chars.next() {
                        *slot = ch;
                        if let Some(d) = ch.to_digit(16) {
                            val = (val << 4) | d;
                        } else {
                            valid = false;
                            break;
                        }
                    } else {
                        valid = false;
                        break;
                    }
                }
                if valid && let Some(ch) = char::from_u32(val) {
                    out.push(ch);
                } else {
                    out.push('u');
                    for &ch in &buf {
                        if ch != '\0' {
                            out.push(ch);
                        }
                    }
                }
            }
            other => out.push(other),
        }
    }
    out
}

/// 从 mainjs 提取 4 个最长引号字符串：globalText1 / cp0 / cp2 / globalText2
fn extract_immucfg(code: &str) -> [String; 4] {
    let bytes = code.as_bytes();
    let mut quotes = Vec::new();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'"' && (i == 0 || bytes[i - 1] != b'\\') {
            quotes.push(i);
        }
    }
    let mut strs: Vec<String> = Vec::with_capacity(quotes.len() / 2);
    let mut i = 0;
    while i + 1 < quotes.len() {
        strs.push(unescape_js(&code[quotes[i] + 1..quotes[i + 1]]));
        i += 2;
    }
    strs.sort_by_key(|s| std::cmp::Reverse(s.chars().count()));
    let take = |n: usize| strs.get(n).cloned().unwrap_or_default();
    [take(0), take(1), take(2), take(3)]
}

/// 从 mainjs 提取 keyname 数量（站点以 `_$xx=_$yy(0,<num>,_$zz(` 形式给出），缺省 918
fn keyname_num(mainjs: &str) -> usize {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"_\$[\$_A-Za-z0-9]{2}=_\$[\$_A-Za-z0-9]{2}\(0,([0-9]+),_\$[\$_A-Za-z0-9]{2}\(")
            .expect("valid keyname regex")
    });
    RE.captures(mainjs)
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse().ok())
        .unwrap_or(918)
}

/// 站点脚本的游标读取器（mainjs `_$$1` + `_$kx`），按 UTF-16 代码单元读取
struct TextReader {
    chars: Vec<char>,
    pos: usize,
}

impl TextReader {
    fn new(text: &str) -> Self {
        Self {
            chars: text.chars().collect(),
            pos: 0,
        }
    }

    fn code(&mut self) -> u32 {
        let c = self.chars.get(self.pos).copied().unwrap_or('\0');
        self.pos += 1;
        c as u32
    }

    fn line(&mut self, n: usize) -> String {
        let end = (self.pos + n).min(self.chars.len());
        let s: String = self.chars[self.pos.min(end)..end].iter().collect();
        self.pos += n;
        s
    }

    fn list(&mut self) -> Vec<u32> {
        let n = self.code() as usize;
        let out = (0..n)
            .map(|i| self.chars.get(self.pos + i).copied().unwrap_or('\0') as u32)
            .collect();
        self.pos += n;
        out
    }
}

/// 每代码段的 debugger 插入决策（站点脚本里的调试器反调试片段）
struct DebugScd {
    scd: Scd,
    max: u32,
}

impl DebugScd {
    fn new(nsd: u32) -> Self {
        let mut scd = Scd::new(nsd);
        let max = scd.next() % 10 + 10;
        Self { scd, max }
    }

    fn tick(&mut self) -> bool {
        self.max -= 1;
        if self.max == 0 {
            self.max = self.scd.next() % 10 + 10;
            return self.max < 64;
        }
        false
    }
}

/// 拼接缓冲区：写入单个 `String`，同时记录片段数与字符数
struct CodeBuf {
    text: String,
    /// 片段数（站点侧以其作为 debugger 位置参数）
    pieces: usize,
    /// 已写入的字符数（站点侧用 `join('').length`）
    chars: usize,
}

impl CodeBuf {
    fn with_capacity(cap: usize) -> Self {
        Self {
            text: String::with_capacity(cap),
            pieces: 0,
            chars: 0,
        }
    }

    fn push(&mut self, piece: &str) {
        self.pieces += 1;
        self.chars += piece.chars().count();
        self.text.push_str(piece);
    }

    fn push_num(&mut self, n: usize) {
        self.pieces += 1;
        let before = self.text.len();
        let _ = write!(self.text, "{n}");
        self.chars += self.text.len() - before;
    }

    fn push_repeat(&mut self, piece: &str, times: usize) {
        self.pieces += 1;
        self.chars += piece.chars().count() * times;
        for _ in 0..times {
            self.text.push_str(piece);
        }
    }
}

/// 一次解码共用的两张符号表与全局 opmate
struct Context<'a> {
    keycodes: &'a [String],
    keynames: &'a [String],
    globals: (u32, u32),
}

/// 从 r2mka keycode 原文中取出被引号包裹的任务表文本（站点 `_parseR2mka`）
fn parse_r2mka_raw(raw: &str) -> Option<String> {
    let start = raw.find('"')? + 1;
    let end = raw.rfind('"')?;
    if end <= start {
        return None;
    }
    Some(unescape_js(&raw[start..end]))
}

/// 站点侧以 `undefined` 形式参与字符串拼接的下标（越界即此值）
fn at(list: &[String], idx: u32) -> &str {
    list.get(idx as usize)
        .map(String::as_str)
        .unwrap_or("undefined")
}

/// 重建站点代码与其中的函数表
pub(crate) struct Coder {
    nsd: u32,
    keyname_num: usize,
    global_text1: String,
    global_text2: String,
    /// 与站点一致的函数顺序，元素为函数源码
    functions_name_sort: Vec<String>,
    /// 主代码在 `code` 中的起止字符偏移
    main_function_idx: Option<[usize; 2]>,
    /// 重建出的可读代码
    code: String,
    /// keyname 表（站点 `cp[1]`），Tag 2 取值要用
    keynames: Vec<String>,
    /// 任务表原文，Tag 2 取值要用
    r2mka_text: Option<String>,
}

impl Coder {
    pub(crate) fn new(nsd: u32, mainjs: &str) -> Self {
        let [global_text1, _cp0, _cp2, global_text2] = extract_immucfg(mainjs);
        Self {
            nsd,
            keyname_num: keyname_num(mainjs),
            global_text1,
            global_text2,
            functions_name_sort: Vec::new(),
            main_function_idx: None,
            code: String::new(),
            keynames: Vec::new(),
            r2mka_text: None,
        }
    }

    pub(crate) fn run(&mut self) {
        let keynames = gren_keys(self.keyname_num, self.nsd);
        let mut buf = CodeBuf::with_capacity(self.global_text1.len() * 2 + 1024);
        let mut scd = Scd::new(self.nsd);
        let mut r = TextReader::new(&self.global_text1);

        // 6 个 opmate 标志
        let _g_e4 = r.code();
        let _g_sc = r.code();
        let g_dk = r.code();
        let g_kv = r.code();
        let _g_cr = r.code();
        let _g_un = r.code();

        let (hi, lo) = (r.code(), r.code());
        let k_len = hi as usize * 55295 + lo as usize;
        let mut keycodes: Vec<String> = r.line(k_len).split('\u{101}').map(String::from).collect();
        r.code();
        let (hi, lo) = (r.code(), r.code());
        let r2mka_raw = r.line(hi as usize * 55295 + lo as usize);
        self.r2mka_text = parse_r2mka_raw(&r2mka_raw);
        keycodes.push(r2mka_raw);

        let ctx = Context {
            keycodes: &keycodes,
            keynames: &keynames,
            globals: (g_dk, g_kv),
        };
        let code_num = r.code() as usize;
        for current in 0..code_num {
            let mut dbg = DebugScd::new(self.nsd);
            self.gren(&mut r, current, &mut buf, &ctx, &mut scd, &mut dbg);
        }

        buf.push_repeat("}", 10usize.saturating_sub(code_num.saturating_sub(1)));
        if let Some(idx) = self.main_function_idx.as_mut() {
            idx[1] = buf.chars;
        }

        let mut g2 = TextReader::new(&self.global_text2);
        Self::parse_global_text2(&mut g2, &mut buf, &keynames);
        buf.push("})($_ts.scj,$_ts.aebi);");
        self.code = buf.text;
        self.keynames = keynames;
    }

    /// 由任务表与 keyname 表算出 Tag 2 的 4 字节（站点 `fixedValue20`）
    pub(crate) fn tag2(&self, keys: &super::RuishuKeys) -> Result<[u8; 4], SessionError> {
        let text = self
            .r2mka_text
            .as_deref()
            .ok_or_else(|| SessionError::RuishuError {
                msg: "mainjs r2mka task table missing".to_string(),
            })?;
        super::r2mka::tag2(text, &self.keynames, keys)
    }

    /// 代码段生成（mainjs `_$g6` 及其后续循环）
    fn gren(
        &mut self,
        r: &mut TextReader,
        current: usize,
        buf: &mut CodeBuf,
        ctx: &Context,
        scd: &mut Scd,
        dbg: &mut DebugScd,
    ) {
        let (g_dk, g_kv) = ctx.globals;
        buf.push_repeat("\n", scd.next() as usize % 5);

        let m: Vec<u32> = (0..8).map(|_| r.code()).collect(); // ku s6 bs sq jw sg cu aw
        let list_k = r.list();
        let list_h = r.list();
        let list_c = r.list();
        let mut pairs: Vec<[u32; 2]> = list_c
            .chunks(2)
            .map(|c| [c[0], c.get(1).copied().unwrap_or(u32::MAX)])
            .collect();
        array_shuffle(&mut pairs, scd);
        let shuffled_pairs = pairs;

        let bf = r.code();
        let aebi = r.list();

        let func_count = r.code() as usize;
        let mut func_segs: Vec<Vec<u32>> = (0..func_count).map(|_| r.list()).collect();
        array_shuffle(&mut func_segs, scd);
        let shuffled_funcs = func_segs;
        let opc_count = r.code() as usize;
        let opc_impls: Vec<Vec<u32>> = (0..opc_count).map(|_| r.list()).collect();

        if current > 0 {
            if self.main_function_idx.is_none() {
                self.main_function_idx = Some([buf.chars, 0]);
            }
            buf.push("function ");
            buf.push(at(ctx.keynames, m[4]));
            buf.push("(");
            buf.push(at(ctx.keynames, m[1]));
            for it in &list_k {
                buf.push(",");
                buf.push(at(ctx.keynames, *it));
            }
            buf.push("){");
        } else {
            buf.push("(function(");
            buf.push(at(ctx.keynames, g_dk));
            buf.push(",");
            buf.push(at(ctx.keynames, g_kv));
            buf.push("){var ");
            buf.push(at(ctx.keynames, m[1]));
            buf.push("=0;");
        }

        let mut fn_map: Vec<(&str, String)> = Vec::new();
        for p in &shuffled_pairs {
            let name = at(ctx.keynames, p[0]);
            let args = at(ctx.keynames, m[3]);
            let arg = if p[1] == u32::MAX {
                "undefined".to_string()
            } else {
                p[1].to_string()
            };
            let body = format!(
                "function {name}(){{var {args}=[{arg}];Array.prototype.push.apply({args},arguments);\
                 return {}.apply(this,{args});}}",
                at(ctx.keynames, m[5])
            );
            buf.push(&body);
            fn_map.push((name, body));
        }

        for item in &shuffled_funcs {
            let mut i = 0;
            while i + 1 < item.len() {
                buf.push(at(ctx.keycodes, item[i]));
                buf.push(at(ctx.keynames, item[i + 1]));
                i += 2;
            }
            buf.push(at(ctx.keycodes, item.last().copied().unwrap_or(u32::MAX)));
        }

        if !list_h.is_empty() {
            for (i, it) in list_h.iter().enumerate() {
                buf.push(if i == 0 { "var " } else { "," });
                buf.push(at(ctx.keynames, *it));
            }
            buf.push(";");
        }

        buf.push("var ");
        buf.push(at(ctx.keynames, m[2]));
        buf.push(",");
        buf.push(at(ctx.keynames, m[6]));
        buf.push(",");
        buf.push(at(ctx.keynames, m[0]));
        buf.push("=");
        buf.push(at(ctx.keynames, m[1]));
        buf.push(",");
        buf.push(at(ctx.keynames, m[7]));
        buf.push("=");
        buf.push(at(ctx.keynames, g_kv));
        buf.push("[");
        buf.push_num(current);
        buf.push("];");
        buf.push("while(1){");
        buf.push(at(ctx.keynames, m[6]));
        buf.push("=");
        buf.push(at(ctx.keynames, m[7]));
        buf.push("[");
        buf.push(at(ctx.keynames, m[0]));
        buf.push("++];");
        buf.push("if(");
        buf.push(at(ctx.keynames, m[6]));
        buf.push("<");
        buf.push_num(bf as usize);
        buf.push("){");

        if (1..=4).contains(&current) {
            // 站点侧此处抛异常会被吞掉，已入表项保留
            self.functions_sort(
                current,
                &fn_map,
                shuffled_pairs.len(),
                &opc_impls,
                &aebi,
                ctx,
            );
        }

        let cu = at(ctx.keynames, m[6]);
        Self::if_else(0, bf as usize, buf, &opc_impls, ctx, cu, dbg);
        buf.push("}else ");
        buf.push(";");
        buf.push("}");
    }

    /// 收集与站点一致的函数顺序（`functionsNameSort`）
    fn functions_sort(
        &mut self,
        current: usize,
        fn_map: &[(&str, String)],
        pairs_len: usize,
        opc_impls: &[Vec<u32>],
        aebi: &[u32],
        ctx: &Context,
    ) {
        let get_name = |idx: u32| -> Option<usize> {
            let arr = opc_impls.get(idx as usize)?;
            if arr.len() != 5 {
                return None;
            }
            let name = ctx.keynames.get(arr[3] as usize)?;
            fn_map.iter().position(|(n, _)| n == name)
        };

        let mut start = 0usize;
        if current == 1 {
            for it in ctx.keycodes.iter().filter(|it| is_index_keycode(it)) {
                let s: usize = it[1..it.len() - 2].parse().unwrap_or_default();
                if s + pairs_len > aebi.len() {
                    continue;
                }
                if !aebi[s..s + pairs_len]
                    .iter()
                    .all(|i| get_name(*i).is_some())
                {
                    continue;
                }
                start = s;
            }
        }

        let end = (start + pairs_len).min(aebi.len());
        for idx in &aebi[start.min(end)..end] {
            match get_name(*idx) {
                Some(i) => self.functions_name_sort.push(fn_map[i].1.clone()),
                None => return,
            }
        }
    }

    /// 站点侧按 opcode 区段展开 `if/else` 分派
    fn if_else(
        start: usize,
        end: usize,
        buf: &mut CodeBuf,
        impls: &[Vec<u32>],
        ctx: &Context,
        cu: &str,
        dbg: &mut DebugScd,
    ) {
        const STEPS: [usize; 8] = [4, 16, 64, 256, 1024, 4096, 16384, 65536];
        let diff = end.saturating_sub(start);
        if diff == 0 {
            return;
        }
        if diff == 1 {
            append_impl(start, buf, impls, ctx, dbg);
            return;
        }
        if diff <= 4 {
            let mut text = "if(";
            let mut start = start;
            let last = end - 1;
            while start < last {
                buf.push(text);
                buf.push(cu);
                buf.push("===");
                buf.push_num(start);
                buf.push("){");
                append_impl(start, buf, impls, ctx, dbg);
                text = "}else if(";
                start += 1;
            }
            buf.push("}else{");
            append_impl(start, buf, impls, ctx, dbg);
            buf.push("}");
            return;
        }

        let step = STEPS
            .iter()
            .position(|it| diff <= *it)
            .and_then(|i| i.checked_sub(1))
            .map(|i| STEPS[i])
            .unwrap_or(0);
        let mut text = "if(";
        let mut start = start;
        while start + step < end {
            buf.push(text);
            buf.push(cu);
            buf.push("<");
            buf.push_num(start + step);
            buf.push("){");
            Self::if_else(start, start + step, buf, impls, ctx, cu, dbg);
            text = "}else if(";
            start += step;
        }
        buf.push("}else{");
        Self::if_else(start, end, buf, impls, ctx, cu, dbg);
        buf.push("}");
    }

    fn parse_global_text2(r: &mut TextReader, buf: &mut CodeBuf, keynames: &[String]) {
        r.code();
        let kc2: Vec<String> = {
            let kc2_len = r.code() as usize;
            r.line(kc2_len).split('\u{101}').map(String::from).collect()
        };
        let list = r.list();
        let mut i = 0;
        while i + 1 < list.len() {
            buf.push(at(&kc2, list[i]));
            buf.push(at(keynames, list[i + 1]));
            i += 2;
        }
        buf.push(at(&kc2, list.last().copied().unwrap_or(u32::MAX)));
    }

    /// 用当前会话 `keys[33]`/`keys[34]` 指定函数与代码切片，算出 Tag 7 的 16 位校验和
    pub(crate) fn code_uid(&self, keys: &super::RuishuKeys) -> Result<u16, SessionError> {
        let func_idx = parse_ascii_int(keys.keys.get(33))? as usize;
        let slice_mul = parse_ascii_int(keys.keys.get(34))? as usize;
        let func =
            self.functions_name_sort
                .get(func_idx)
                .ok_or_else(|| SessionError::RuishuError {
                    msg: format!("code_uid function index {func_idx} out of range"),
                })?;
        let [start, end] = self
            .main_function_idx
            .ok_or_else(|| SessionError::RuishuError {
                msg: "mainjs main function not located".to_string(),
            })?;
        // 偏移按字符计，主代码长度即区间长度
        let len = end.saturating_sub(start) / 100;
        let one = super::crc32(func.as_bytes());
        let slice_start = start + len * slice_mul;
        let slice_end = slice_start + len;
        let mut byte_start = None;
        let mut byte_end = None;
        for (char_idx, (byte_idx, _)) in self.code.char_indices().enumerate() {
            if char_idx == slice_start {
                byte_start = Some(byte_idx);
            }
            if char_idx == slice_end {
                byte_end = Some(byte_idx);
                break;
            }
        }
        let slice_bytes = match (byte_start, byte_end) {
            (Some(s), Some(e)) => &self.code.as_bytes()[s..e],
            (Some(s), None) => &self.code.as_bytes()[s..],
            _ => &[],
        };
        let two = super::crc32(slice_bytes);
        Ok(((one ^ two) & 0xffff) as u16)
    }
}

/// 站点侧按 `if/else` 区段展开一段 opcode 实现
fn append_impl(
    idx: usize,
    buf: &mut CodeBuf,
    impls: &[Vec<u32>],
    ctx: &Context,
    dbg: &mut DebugScd,
) {
    if dbg.tick() {
        buf.push("debugger;");
    }
    let Some(arr) = impls.get(idx) else {
        return;
    };
    let len = arr.len() - (arr.len() % 2);
    let mut i = 0;
    while i < len {
        buf.push(at(ctx.keycodes, arr[i]));
        buf.push(at(ctx.keynames, arr[i + 1]));
        i += 2;
    }
    if arr.len() != len {
        buf.push(at(ctx.keycodes, arr[len]));
    }
}

/// 站点侧形如 `(123);` 的 keycode（用于定位 `aebi` 起点）
fn is_index_keycode(it: &str) -> bool {
    it.starts_with('(')
        && it.ends_with(");")
        && it.len() > 3
        && it[1..it.len() - 2].bytes().all(|b| b.is_ascii_digit())
}

fn parse_ascii_int(k: Option<&Vec<u8>>) -> Result<u32, SessionError> {
    let k = k.ok_or_else(|| SessionError::RuishuError {
        msg: "missing keys for code_uid".to_string(),
    })?;
    std::str::from_utf8(k)
        .ok()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| SessionError::RuishuError {
            msg: "non-numeric key for code_uid".to_string(),
        })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[derive(serde::Deserialize)]
    struct Fixture {
        keyname_num: usize,
        scd_seed_85762_first8: Vec<u32>,
        shuffle_0_9_seed_85762: Vec<u32>,
        gren_keys_10_seed_85762: Vec<String>,
        vectors: BTreeMap<String, Vector>,
    }

    #[derive(serde::Deserialize)]
    struct Vector {
        nsd: u32,
        cd: String,
        code_len: usize,
        code_crc32: u32,
        fn_sort_len: usize,
        main_function_idx: [usize; 2],
        func_idx: usize,
        slice_mul: usize,
        main_code_len: usize,
        code_uid: u16,
    }

    fn fixture() -> Fixture {
        serde_json::from_str(include_str!("../../../tests/fixtures/ruishu_coder.json")).unwrap()
    }

    #[test]
    fn scd_sequence_matches_reference() {
        let f = fixture();
        let mut scd = Scd::new(85762);
        let got: Vec<u32> = (0..f.scd_seed_85762_first8.len())
            .map(|_| scd.next())
            .collect();
        assert_eq!(got, f.scd_seed_85762_first8);
    }

    #[test]
    fn array_shuffle_matches_reference() {
        let f = fixture();
        let mut arr: Vec<u32> = (0..10).collect();
        array_shuffle(&mut arr, &mut Scd::new(85762));
        assert_eq!(arr, f.shuffle_0_9_seed_85762);
    }

    #[test]
    fn gren_keys_matches_reference() {
        let f = fixture();
        let names = gren_keys(10, 85762);
        assert_eq!(names.len(), 10);
        assert_eq!(names, f.gren_keys_10_seed_85762);
    }

    #[test]
    fn unescape_js_matches_js_semantics() {
        assert_eq!(unescape_js(r"a\nb\t\x41\u0042"), "a\nb\tAB");
        assert_eq!(unescape_js(r#"\'\"\\\/"#), "'\"\\/");
        // 非特殊字符是标识转义
        assert_eq!(unescape_js(r"a\ĸb"), "aĸb");
        // 残缺的十六进制转义整段回退
        assert_eq!(unescape_js(r"a\xZZb"), "axZZb");
        // 裸换行的字面量站点会退回原文
        assert_eq!(unescape_js("a\nb"), "a\nb");
    }

    #[test]
    fn extract_immucfg_picks_four_longest() {
        let js = r#"var a="ss",b="the longest one",c="second longest",d="third here",e="fourth";"#;
        let [g1, cp0, cp2, g2] = extract_immucfg(js);
        assert_eq!(
            [g1.as_str(), cp0.as_str(), cp2.as_str(), g2.as_str()],
            ["the longest one", "second longest", "third here", "fourth"]
        );
    }

    #[test]
    fn keyname_num_reads_site_form() {
        let js = "..._$ab=_$cd(0,1151,_$ef(...";
        assert_eq!(keyname_num(js), 1151);
        assert_eq!(keyname_num("no match here"), 918);
    }

    #[test]
    fn is_index_keycode_matches_site_form() {
        assert!(is_index_keycode("(123);"));
        assert!(!is_index_keycode("(12a);"));
        assert!(!is_index_keycode("()"));
        assert!(!is_index_keycode("(123)"));
    }

    /// 完整对照：需要站点脚本（通过环境变量 `RSMYCQU_MAINJS` 指定路径）
    #[test]
    #[ignore = "requires external mainjs script specified via RSMYCQU_MAINJS"]
    fn code_uid_matches_reference_when_mainjs_available() {
        let path = std::env::var("RSMYCQU_MAINJS")
            .expect("RSMYCQU_MAINJS environment variable must be set to mainjs.js path");
        let mainjs = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read RSMYCQU_MAINJS from {path}: {e}"));
        let f = fixture();
        assert_eq!(keyname_num(&mainjs), f.keyname_num);

        for (name, v) in &f.vectors {
            let mut coder = Coder::new(v.nsd, &mainjs);
            coder.run();
            assert_eq!(coder.code.chars().count(), v.code_len, "code_len {name}");
            assert_eq!(
                super::super::crc32(coder.code.as_bytes()),
                v.code_crc32,
                "code_crc32 {name}"
            );
            assert_eq!(
                coder.functions_name_sort.len(),
                v.fn_sort_len,
                "fn_sort_len {name}"
            );
            assert_eq!(
                coder.main_function_idx,
                Some(v.main_function_idx),
                "main_function_idx {name}"
            );
            let [start, end] = v.main_function_idx;
            assert_eq!(end - start, v.main_code_len, "main_code_len {name}");

            let keys = super::super::extract_keys(&v.cd).unwrap();
            assert_eq!(
                parse_ascii_int(keys.keys.get(33)).unwrap() as usize,
                v.func_idx,
                "func_idx {name}"
            );
            assert_eq!(
                parse_ascii_int(keys.keys.get(34)).unwrap() as usize,
                v.slice_mul,
                "slice_mul {name}"
            );
            assert_eq!(
                coder.code_uid(&keys).unwrap(),
                v.code_uid,
                "code_uid {name}"
            );
        }
    }
}
