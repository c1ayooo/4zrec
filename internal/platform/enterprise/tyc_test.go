package enterprise

import "testing"

func TestParseTycAuth(t *testing.T) {
	cases := []struct {
		name       string
		cookie     string
		wantAuthTk string
		wantTycid  string
		wantKeep   bool
	}{
		{
			name:       "完整网页 Cookie 串",
			cookie:     "auth_token=abc123; TYCID=tyc456; sid=xyz",
			wantAuthTk: "abc123",
			wantTycid:  "tyc456",
			wantKeep:   true,
		},
		{
			name:       "auth_token 大小写不敏感",
			cookie:     "AUTH_TOKEN=jwt-upper; TYCID=id",
			wantAuthTk: "jwt-upper",
			wantTycid:  "id",
			wantKeep:   true,
		},
		{
			name:       "X-Auth-Token 头值（空格分隔）",
			cookie:     "x-auth-token eyJhbGciOiJIUzUxMiJ9.token.sig",
			wantAuthTk: "eyJhbGciOiJIUzUxMiJ9.token.sig",
			wantKeep:   false,
		},
		{
			name:       "x-auth-token= 等号分隔",
			cookie:     "x-auth-token=eyJabc.def.ghi",
			wantAuthTk: "eyJabc.def.ghi",
			wantKeep:   false,
		},
		{
			name:       "大小写混合头前缀",
			cookie:     "X-Auth-Token   eyJmixed.case",
			wantAuthTk: "eyJmixed.case",
			wantKeep:   false,
		},
		{
			name:       "裸 JWT",
			cookie:     "eyJhbGciOiJIUzUxMiJ9.raw",
			wantAuthTk: "eyJhbGciOiJIUzUxMiJ9.raw",
			wantKeep:   false,
		},
		{
			name:     "未知形态原样透传",
			cookie:   "some-other-token-value",
			wantKeep: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			authTk, tycid, keep := parseTycAuth(tc.cookie)
			if authTk != tc.wantAuthTk || tycid != tc.wantTycid || keep != tc.wantKeep {
				t.Fatalf("parseTycAuth(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tc.cookie, authTk, tycid, keep, tc.wantAuthTk, tc.wantTycid, tc.wantKeep)
			}
		})
	}
}
