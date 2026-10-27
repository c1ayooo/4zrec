package toolparse

import (
	"regexp"
	"strconv"
	"strings"
)

// johnParser 解析 John the Ripper 半结构化文本输出（C 档：stdout 判定行 + 挂钩层并入的 pot 段）。
// 输入形态：
//   - banner：`Loaded N password hashes with M different salts (FORMAT [实现细节])`、
//     `Warning: detected hash type: "NT", …`；
//   - 破解判定行：`password (login)`（运行期逐条打印，口令与账号以空白+括号分组）；
//   - --show 输出：`login:password:uid:…:::`（passwd/pwdump 档案行，档案名=用户名，口令在第二段）
//     与摘要行 `N password hashes cracked, M left.`；
//   - pot 段：`<hash>:<plain>`（`$NT$hex32` / krb5tgs 等形态；krb 行内嵌 user$realm，
//     与 hashcat 同构，复用其解析）。
//
// 事实映射（档案 §4.5）：破出明文 = 哈希验证实证 → auth/<user>（confirmed，同 fscan 弱口令口径；
// Kerberos 行 user@realm 的 @ 在键里转 -，与 hashcat 侧键形一致）。域凭据以 fact 为准
// （save_ssh/save_db_credential 只覆盖 ssh/db 类）。
type johnParser struct{}

func (johnParser) Tools() []string { return []string{"john"} }

// Match：john 文本输出无注入标志依赖（--pot= 由挂钩层追加），按工具名全量接管
// （解析内部有 banner/进度/摘要行特征门禁）。
func (johnParser) Match(tool string, argv []string) bool { return tool == "john" }

// ── 特征与行形态 ──

// johnFeatureRes 输入特征门禁（零误报）：Loaded banner / 格式识别警告 / 破解进度行 /
// --show 摘要 / 会话收尾。五者皆无 → 判非 john 输出（fail-closed，passwd 之类的
// `user:x:0:0:…` 冒号行不得误判）。
var johnFeatureRes = []*regexp.Regexp{
	regexp.MustCompile(`(?m)^Loaded \d+ password hash`),                 // banner（含 salts/格式段）
	regexp.MustCompile(`(?m)^Warning: detected (hash type|mixed-case)`), // 格式识别警告
	regexp.MustCompile(`(?m)^guesses: \d+\s+time: \d`),                  // 进度行
	regexp.MustCompile(`\d+ password hashes? cracked, \d+ left`),        // --show 摘要
	regexp.MustCompile(`(?m)^Session completed\.?\s*$`),                 // 会话收尾
}

var (
	// johnLoadedRe banner 提取：`Loaded 3 password hashes with no different salts (NT [MD4…])`
	johnLoadedRe  = regexp.MustCompile(`^Loaded (\d+) password hashes.*?\(([A-Za-z0-9_-]+) `)
	johnGuessRe   = regexp.MustCompile(`^guesses: (\d+)`)
	johnSummaryRe = regexp.MustCompile(`^(\d+) password hashes? cracked, (\d+) left`)
	// johnRunLineRe 运行期判定行：`Password1!         (administrator)`（口令单段 + 空白 + 括号账号）
	johnRunLineRe = regexp.MustCompile(`^(\S+)\s+\(([^()\s]{1,64})\)$`)
	johnPotKrbRe  = regexp.MustCompile(`^\$krb5(tgs|asrep)\$(\d{1,2})\$`)
	// johnAccountRe 账号形态（Windows/Unix 账号 + user@domain；拒绝空格与控制字符）
	johnAccountRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@$#-]{0,63}$`)
)

// johnNoiseFirstField john 运行期冒号行的首段白名单外噪音（不会被当账号名落事实）。
var johnNoiseFirstField = map[string]bool{
	"guesses": true, "Warning": true, "Session": true, "Press": true,
	"Loaded": true, "Cost": true, "Using": true, "Note": true, "Node": true, "fork": true,
}

// Parse 解析 john 文本输出。特征门禁不通过 → OK=false 零事实（fail-closed）；
// 通过后逐行提取，单行形态不符仅跳过该行。
func (p johnParser) Parse(stdout, stderr string, rawRef string) (*Result, error) {
	res := &Result{Tool: "john", OK: true, Fields: map[string]any{}, RawRef: rawRef}
	text := fscanANSIRe.ReplaceAllString(stdout, "")
	if strings.TrimSpace(text) == "" {
		return res, nil // 空输入：OK=true 零事实
	}
	if !johnHasFeature(text) {
		res.OK = false
		res.Err = "非 john 输出（无 Loaded/Warning/进度/摘要/Session 特征行）"
		return res, nil
	}

	st := &johnState{seen: map[string]bool{}}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		p.parseLine(st, res, line)
	}

	res.Fields["cracked"] = st.cracked
	if st.loaded > 0 {
		res.Fields["loaded"] = st.loaded
	}
	if st.format != "" {
		res.Fields["format"] = st.format
	}
	if st.left > 0 {
		res.Fields["left"] = st.left
	}
	return res, nil
}

// johnState 单次解析的累积状态。
type johnState struct {
	seen    map[string]bool // 已产事实键去重
	cracked int             // 破解行计数
	loaded  int             // Loaded banner 的哈希数
	left    int             // --show 摘要的剩余数
	format  string          // Loaded banner 的哈希格式（NT/krb5tgs…）
}

// johnHasFeature 特征门禁。
func johnHasFeature(text string) bool {
	for _, re := range johnFeatureRes {
		if re.MatchString(text) {
			return true
		}
	}
	return false
}

// parseLine 单行分发：banner/进度/摘要 → pot 段（krb/其余哈希行）→ 判定行 → --show 档案行。
func (p johnParser) parseLine(st *johnState, res *Result, line string) {
	// banner / 进度 / 摘要行 → 回执摘要字段（不产事实）
	if m := johnLoadedRe.FindStringSubmatch(line); m != nil {
		st.loaded, _ = strconv.Atoi(m[1])
		st.format = m[2]
		return
	}
	if johnGuessRe.MatchString(line) {
		return
	}
	if m := johnSummaryRe.FindStringSubmatch(line); m != nil {
		st.left, _ = strconv.Atoi(m[2])
		return
	}
	// pot 段 Kerberos 行：user$realm/user@realm 内嵌（与 hashcat 同构，复用解析）
	if m := johnPotKrbRe.FindStringSubmatch(line); m != nil {
		hash, plain := hashcatSplitHashPlain(line)
		if plain == "" || len(hash) < 32 {
			return
		}
		st.cracked++
		user, realm := hashcatKrbUserRealm(m[1], hash)
		if user == "" || realm == "" {
			return
		}
		p.addFact(st, res, user+"@"+realm, plain, "Kerberos", line)
		return
	}
	// 运行期判定行：`password (login)`（账号形态校验后落事实）
	if m := johnRunLineRe.FindStringSubmatch(line); m != nil {
		if !johnAccountRe.MatchString(m[2]) {
			return
		}
		st.cracked++
		p.addFact(st, res, m[2], m[1], "", line)
		return
	}
	// pot 段其余哈希行：`<hash>:<plain>`（$NT$ 等无账号形态）→ 只计数不落事实
	if strings.HasPrefix(line, "$") {
		if hash, plain := hashcatSplitHashPlain(line); plain != "" && len(hash) >= 32 {
			st.cracked++
		}
		return
	}
	// --show 档案行：`login:password:uid:…:::`（档案名=用户名，口令为第 2 段；
	// 首段过噪音白名单 + 账号形态 + 非纯 hex32（那是裸哈希行），口令段拒绝首尾空格）
	fields := strings.Split(line, ":")
	if len(fields) < 2 {
		return
	}
	if !johnAccountRe.MatchString(fields[0]) || johnNoiseFirstField[fields[0]] || isHexRunes(fields[0], 32, 32) {
		return
	}
	pass := fields[1]
	if pass == "" || len(pass) > 128 || pass != strings.TrimSpace(pass) || strings.ContainsAny(pass, "\t") {
		return
	}
	st.cracked++
	p.addFact(st, res, fields[0], pass, "", line)
}

// ── 事实构造 ──

// addFact 破解凭据事实（confirmed：明文通过哈希验证即实证）。
func (p johnParser) addFact(st *johnState, res *Result, user, pass, kind, evidence string) {
	key := "auth/" + Sluggify(user)
	if st.seen[key] {
		return
	}
	st.seen[key] = true
	label := kind
	if label == "" && st.format != "" {
		label = st.format
	}
	summary := "john 破解成功: " + user
	if label != "" {
		summary = "john 破解成功 " + label + ": " + user
	}
	body := "账号: " + user + "｜口令: " + pass
	if st.format != "" {
		body += "｜格式: " + st.format
	}
	body += "｜来源: john 破解实证（明文通过哈希验证）｜证据行: " + truncateRunes(evidence, 120)
	res.Facts = append(res.Facts, FactCandidate{
		FactKey:    key,
		Category:   "auth",
		Summary:    summary,
		Body:       body,
		Confidence: "confirmed",
	})
}
