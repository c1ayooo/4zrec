package toolparse

import (
	"regexp"
	"strings"
)

// hashcatParser 解析 hashcat 半结构化文本输出（C 档：stdout 运行期破解行 + 挂钩层并入的 potfile 段）。
// 输入形态（三路同构，一并覆盖）：
//   - 运行期 stdout 破解行 / potfile 破解行 / --show 输出：`<hash>:<plaintext>`——
//     Kerberoast `$krb5tgs$<etype>$*user$realm$spn$…$enc:plain`（13100/19600/19700）、
//     AS-REP `$krb5asrep$<etype>$user@realm…:plain`（18200/19800/19900）、
//     NTLM hex32:plain（1000）与 pwdump 档案行 `user:rid:lm:nt:::plain`、
//     john 兼容 `$NT$hex32:plain`、NetNTLMv2 `user::domain:challenge:proof:blob:plain`（5600）。
//   - 状态面（Status/Recovered/Candidates 圆点填充行）只做回执摘要，不产事实。
//
// 事实映射（档案 §4.5）：破出明文 = 哈希验证实证 → auth/*（confirmed，同 fscan 弱口令口径）：
//   - Kerberos（TGS-REP/AS-REP）→ auth/<user>-<realm>（@ 不在 DB 层 fact_key 字符集，
//     user@realm 保留在摘要/正文；Sluggify 同样把 @ 转 -，两侧解析器键形一致）
//   - NetNTLMv2 → auth/<user>-<domain>
//   - NTLM（pwdump/$NT$ 带账号）→ auth/<user>-ntlm；裸 hex32 无账号 → auth/ntlm-<哈希前缀>
//
// 域凭据以 fact 为准（save_ssh/save_db_credential 只覆盖 ssh/db 类）：Kerberoast/AS-REP 破出的
// 域口令落事实黑板，凭据→横向联动不断在最后一步。
type hashcatParser struct{}

func (hashcatParser) Tools() []string { return []string{"hashcat"} }

// Match：hashcat 文本输出无注入标志依赖（--potfile-path 由挂钩层追加），按工具名全量接管
// （解析内部有 banner/状态行/合法破解行三重特征门禁）。
func (hashcatParser) Match(tool string, argv []string) bool { return tool == "hashcat" }

// ── 特征与行形态 ──

var (
	// hashcatBannerRe banner：`hashcat (v6.2.6) starting in backend mode`
	hashcatBannerRe = regexp.MustCompile(`^hashcat \(v[0-9][^)]*\) starting`)
	// hashcatStatusLineRe 状态面圆点填充行（门禁特征二；Status/Recovered/Candidates/Speed/Hash.Mode）
	hashcatStatusLineRe = regexp.MustCompile(`^(Status|Recovered|Candidates\.#\d+|Speed\.#\d+|Hash\.Mode)\.{3,}\s*:`)
	// 状态面提取（回执摘要）
	hashcatStatusRe     = regexp.MustCompile(`^Status\.{3,}\s*:\s*(\S+)`)
	hashcatRecoveredRe  = regexp.MustCompile(`^Recovered\.{3,}\s*:\s*(\d+)\s*/\s*(\d+)\s*\(([0-9.]+)%\)\s*Digests`)
	hashcatCandidatesRe = regexp.MustCompile(`^Candidates\.#\d+\.{3,}\s*:\s*(\S+)`)

	// 破解行（门禁特征三，须过 hash 形态正则校验）
	hashcatKrbPrefixRe  = regexp.MustCompile(`^\$krb5(tgs|asrep)\$(\d{1,2})\$`) // Kerberos 族前缀
	hashcatUserRealmRe  = regexp.MustCompile(`([A-Za-z0-9][A-Za-z0-9._-]{0,63})@([A-Za-z0-9][A-Za-z0-9._-]{1,63})`)
	hashcatNTLMRe       = regexp.MustCompile(`^([0-9a-fA-F]{32}):(\S+)$`) // 裸 NTLM hex32:plain
	hashcatNTDollarRe   = regexp.MustCompile(`^\$NT\$([0-9a-fA-F]{32}):(\S+)$`)
	hashcatPwdumpRe     = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._@$#-]{0,63}):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::(\S+)$`)
	hashcatHexGateRe    = regexp.MustCompile(`^([0-9a-fA-F]{32,}):(\S+)$`)       // hex≥32 兜底门禁（不产事实）
	hashcatDollarHashRe = regexp.MustCompile(`^\$[A-Za-z0-9][A-Za-z0-9_.+-]*\$`) // $ 格式前缀兜底门禁
	// hashcatAccountRe 账号/域名形态（Windows/Unix 账号 + user@domain；拒绝空格与控制字符）
	hashcatAccountRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@$#-]{0,63}$`)
)

// Kerberos etype → hashcat 模式号速查（13100/18200 经典 RC4，AES 变体 19600-19900）。
var (
	hashcatTgsMode   = map[string]string{"23": "13100", "17": "19600", "18": "19700"}
	hashcatAsrepMode = map[string]string{"23": "18200", "17": "19800", "18": "19900"}
)

// Parse 解析 hashcat 文本输出。特征门禁不通过 → OK=false 零事实（fail-closed，
// 普通命令输出的冒号行零误报）；通过后逐行提取，单行形态不符仅跳过该行。
func (p hashcatParser) Parse(stdout, stderr string, rawRef string) (*Result, error) {
	res := &Result{Tool: "hashcat", OK: true, Fields: map[string]any{}, RawRef: rawRef}
	text := fscanANSIRe.ReplaceAllString(stdout, "")
	if strings.TrimSpace(text) == "" {
		return res, nil // 空输入：OK=true 零事实
	}
	st := &hashcatState{seen: map[string]bool{}}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		p.parseLine(st, res, line)
	}
	if !st.gate {
		res.OK = false
		res.Err = "非 hashcat 输出（无 banner/状态行/合法 hash:plain 破解行）"
		return res, nil
	}
	res.Fields["cracked"] = st.cracked
	res.Fields["kerberos"] = st.kerberos
	if st.status != "" {
		res.Fields["status"] = st.status
	}
	if st.recovered != "" {
		res.Fields["recovered"] = st.recovered
	}
	if st.candidates != "" {
		res.Fields["candidates"] = st.candidates
	}
	return res, nil
}

// hashcatState 单次解析的累积状态。
type hashcatState struct {
	seen       map[string]bool // 已产事实键去重
	gate       bool            // 特征门禁（banner/状态行/合法破解行任一命中）
	cracked    int             // 合法破解行计数
	kerberos   int             // Kerberos 族破解计数
	status     string          // 状态面摘要（Status 行）
	recovered  string          // 状态面摘要（Recovered Digests 行）
	candidates string          // 状态面摘要（首条 Candidates 行）
}

// parseLine 单行分发：状态面 → 破解行。
func (p hashcatParser) parseLine(st *hashcatState, res *Result, line string) {
	// banner（门禁特征一）
	if hashcatBannerRe.MatchString(line) {
		st.gate = true
		return
	}
	// 状态面（门禁特征二）：只做回执摘要
	if m := hashcatStatusRe.FindStringSubmatch(line); m != nil {
		st.gate = true
		st.status = m[1]
		return
	}
	if m := hashcatRecoveredRe.FindStringSubmatch(line); m != nil {
		st.gate = true
		st.recovered = m[1] + "/" + m[2] + " (" + m[3] + "%)"
		return
	}
	if m := hashcatCandidatesRe.FindStringSubmatch(line); m != nil {
		st.gate = true
		if st.candidates == "" {
			st.candidates = truncateRunes(m[1], 32)
		}
		return
	}
	if hashcatStatusLineRe.MatchString(line) {
		st.gate = true
		return
	}
	// 破解行（门禁特征三，须过 hash 形态校验）
	p.parseCrackLine(st, res, line)
}

// parseCrackLine 破解行按形态族分发：Kerberos / $NT$ / pwdump / NetNTLMv2 / 裸 NTLM /
// 其余合法 hash 形态（只计门禁与计数，不产事实——类型范围外无账号可落）。
func (p hashcatParser) parseCrackLine(st *hashcatState, res *Result, line string) {
	// Kerberos 族：$ 前缀形态，user/realm 内嵌哈希
	if m := hashcatKrbPrefixRe.FindStringSubmatch(line); m != nil {
		hash, plain := hashcatSplitHashPlain(line)
		if plain == "" || len(hash) < 32 {
			return
		}
		st.gate = true
		st.cracked++
		st.kerberos++
		p.addKrbFact(st, res, m[1], m[2], hash, plain)
		return
	}
	// $NT$ 前缀（john 兼容形态）→ NTLM(1000)
	if m := hashcatNTDollarRe.FindStringSubmatch(line); m != nil {
		st.gate = true
		st.cracked++
		p.addNTLMFact(st, res, "", m[1], m[2])
		return
	}
	// pwdump 档案行：user:rid:lm:nt:::plain → NTLM(1000) 带账号
	if m := hashcatPwdumpRe.FindStringSubmatch(line); m != nil {
		st.gate = true
		st.cracked++
		p.addNTLMFact(st, res, m[1], m[4], m[5])
		return
	}
	// NetNTLMv2(5600)：user::domain:challenge:proof:blob:plain
	if user, domain, plain, ok := hashcatParseNetNTLMv2(line); ok {
		st.gate = true
		st.cracked++
		p.addCredFact(st, res, "auth/"+Sluggify(user)+"-"+Sluggify(domain), user+"@"+domain, plain,
			"NetNTLMv2(5600)", "NetNTLMv2（hashcat -m 5600）")
		return
	}
	// 裸 NTLM hex32:plain（1000）
	if m := hashcatNTLMRe.FindStringSubmatch(line); m != nil {
		st.gate = true
		st.cracked++
		p.addNTLMFact(st, res, "", m[1], m[2])
		return
	}
	// 兜底门禁：其余合法 hash 形态（hex≥32 或 $ 前缀）:plain——类型范围外，不产事实
	if hashcatHexGateRe.MatchString(line) {
		st.gate = true
		st.cracked++
		return
	}
	if hashcatDollarHashRe.MatchString(line) {
		if hash, plain := hashcatSplitHashPlain(line); plain != "" && len(hash) >= 32 {
			st.gate = true
			st.cracked++
		}
	}
}

// ── 事实构造 ──

// addKrbFact Kerberos 族事实：13100/18200 及 AES 变体，user$realm/user@realm 内嵌解析。
func (p hashcatParser) addKrbFact(st *hashcatState, res *Result, kind, etype, hash, plain string) {
	user, realm := hashcatKrbUserRealm(kind, hash)
	if user == "" || realm == "" {
		return // 内嵌账号不可解析（形态裁剪/截断）→ 只计数不落事实
	}
	label, mode := "Kerberoast TGS-REP", hashcatTgsMode[etype]
	if kind != "tgs" {
		label, mode = "AS-REP Roast", hashcatAsrepMode[etype]
	}
	typeLabel := label
	detail := label + " etype " + etype
	if mode != "" {
		typeLabel += "(" + mode + ")"
		detail += "（hashcat -m " + mode + "）"
	}
	p.addCredFact(st, res, "auth/"+Sluggify(user)+"-"+Sluggify(realm), user+"@"+realm, plain,
		typeLabel, detail+"｜哈希前缀: "+truncateRunes(hash, 48))
}

// addNTLMFact NTLM(1000) 事实：pwdump/$NT$ 带账号 → auth/<user>-ntlm；裸哈希 → auth/ntlm-<前缀>。
func (p hashcatParser) addNTLMFact(st *hashcatState, res *Result, user, hash, plain string) {
	who := user
	key := "auth/ntlm-" + strings.ToLower(hash[:12]) // 裸哈希无账号，键用前缀防键超长
	if user != "" {
		key = "auth/" + Sluggify(user) + "-ntlm"
	} else {
		who = strings.ToLower(hash[:12]) + "…（无账号信息）"
	}
	p.addCredFact(st, res, key, who, plain, "NTLM(1000)", "NTLM（hashcat -m 1000）｜哈希: "+strings.ToLower(hash))
}

// addCredFact 破解凭据事实统一构造（confirmed：明文通过哈希验证即实证）。
func (p hashcatParser) addCredFact(st *hashcatState, res *Result, key, who, plain, typeLabel, bodyDetail string) {
	if st.seen[key] {
		return
	}
	st.seen[key] = true
	res.Facts = append(res.Facts, FactCandidate{
		FactKey:    key,
		Category:   "auth",
		Summary:    "hashcat 破解成功 " + typeLabel + ": " + who,
		Body:       "账号: " + who + "｜口令: " + plain + "｜类型: " + bodyDetail + "｜来源: hashcat 破解实证",
		Confidence: "confirmed",
	})
}

// ── 小工具 ──

// hashcatSplitHashPlain 按最后一个冒号拆 <hash>:<plaintext>（Kerberos 哈希的 SPN 段可含冒号，
// 明文段不含）；口令含空格时 potfile 语义有歧义，fail-closed 跳过。
func hashcatSplitHashPlain(line string) (string, string) {
	i := strings.LastIndexByte(line, ':')
	if i < 0 {
		return line, ""
	}
	hash, plain := line[:i], line[i+1:]
	if plain == "" || strings.ContainsAny(plain, " \t") || len(plain) > 128 {
		return line, ""
	}
	return hash, plain
}

// hashcatKrbUserRealm 从 Kerberos 哈希内嵌段解 user/realm：
//   - tgs：$ 分段 `$krb5tgs$<etype>$*user$realm$spn$…` → 第 4/5 段（user 前缀 * 剥离）
//   - asrep：`$krb5asrep$<etype>$user@realm…`（分隔符 $ 与 : 两代形态都有）→ user@realm 子串
func hashcatKrbUserRealm(kind, hash string) (string, string) {
	if kind == "tgs" {
		parts := strings.Split(hash, "$")
		if len(parts) < 5 {
			return "", ""
		}
		user, realm := strings.TrimPrefix(parts[3], "*"), parts[4]
		if hashcatAccountRe.MatchString(user) && hashcatAccountRe.MatchString(realm) {
			return user, realm
		}
		return "", ""
	}
	if m := hashcatUserRealmRe.FindStringSubmatch(hash); m != nil {
		return m[1], m[2]
	}
	return "", ""
}

// hashcatParseNetNTLMv2 解析 NetNTLMv2(5600) potfile 行 `user::domain:challenge:proof:blob:plain`
// （7 段、user 后空段是格式特征；challenge/proof/blob 均 hex，proof 为 32 位）。
func hashcatParseNetNTLMv2(line string) (user, domain, plain string, ok bool) {
	fields := strings.Split(line, ":")
	if len(fields) != 7 || fields[1] != "" {
		return "", "", "", false
	}
	user, domain, plain = fields[0], fields[2], fields[6]
	if !hashcatAccountRe.MatchString(user) || !hashcatAccountRe.MatchString(domain) {
		return "", "", "", false
	}
	if !isHexRunes(fields[3], 8, 32) || !isHexRunes(fields[4], 32, 32) || !isHexRunes(fields[5], 16, 4096) {
		return "", "", "", false
	}
	if plain == "" || strings.ContainsAny(plain, " \t") {
		return "", "", "", false
	}
	return user, domain, plain, true
}

// isHexRunes 判定纯十六进制串且长度在 [min,max]（NetNTLMv2/哈希段校验）。
func isHexRunes(s string, min, max int) bool {
	if len(s) < min || len(s) > max {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}
