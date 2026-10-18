// creds_tools.go 凭据验证工具族:云 AK/SK 最小化只读验证、数据库/SSH 凭据实连、
// GitHub 泄露 dork。验证类工具只做「凭据有效性/只读探测」,破坏性操作不在本族。
// cloudverify/githubdork 直接搬自 4zreco;dbprobe/sshprobe 按 4zrec 依赖面重写
// (pgx+裸 RESP+x/crypto/ssh,不引 mysql/mongo 驱动)。GitHub Token 走 settings
// +GITHUB_TOKEN 环境变量优先。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/internal/capability/cloud/creds"
	"github.com/c1ayooo/4zrec/internal/domain/db"
	actool "github.com/c1ayooo/4zrec/internal/toolface/tools"
)

const githubTokenSetting = "githubsearch.token"

// credsRoE applies the same project authorization check as the other active
// network tools. Without it, credential_verify_db/ssh (Permissions=Allowed)
// bypass the asset fence and can probe loopback/internal hosts.
func (s *Server) credsRoE(ctx context.Context, host string) string {
	projectID := s.roeProjectID(ctx, 0)
	if projectID <= 0 {
		return ""
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "host 必填"
	}
	var domains, ips []string
	if net.ParseIP(host) != nil {
		ips = []string{host}
	} else {
		domains = []string{host}
	}
	if !s.m.pg.AuthorizedTarget(projectID, domains, ips) {
		return fmt.Sprintf("【RoE 拒绝】目标 %s 不在项目 %d 授权范围内", host, projectID)
	}
	return ""
}

// githubDorkClient 构造 dork 客户端(token: env > settings;BaseURL 可被测试注入)。
func (s *Server) githubDorkClient() *creds.Client {
	return creds.NewClient(func() string {
		if v := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); v != "" {
			return v
		}
		if s.m != nil && s.m.pg != nil {
			if v, ok, err := s.m.pg.GetSetting(githubTokenSetting); err == nil && ok {
				return strings.TrimSpace(v)
			}
		}
		return ""
	})
}

// toolCredVerifyCloud 云 AK/SK 最小化只读验证(阿里/腾讯/AWS/华为/火山)。
func (s *Server) toolCredVerifyCloud() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "credential_verify_cloud",
		Description: "云平台 AK/SK 验证(最小化只读调用:阿里/腾讯/AWS/华为/火山,一次 GetCallerIdentity/GetUser 级查询):" +
			"返回凭据有效性、账号标识与只读权限面结论。只验证不操作;发现的有效凭据建议立即登记并通知资产方轮换。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"provider":   map[string]any{"type": "string", "description": "aliyun/tencent/aws/huawei/volc"},
				"access_key": map[string]any{"type": "string", "description": "AccessKeyID"},
				"secret_key": map[string]any{"type": "string", "description": "SecretKey"},
			},
			"required": []string{"provider", "access_key", "secret_key"},
		},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision { return actool.Allowed() },
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				Provider  string `json:"provider"`
				AccessKey string `json:"access_key"`
				SecretKey string `json:"secret_key"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			res, err := creds.Verify(ctx, &http.Client{Timeout: 15 * time.Second}, in.Provider, in.AccessKey, in.SecretKey)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "厂商 %s / 状态 %s\n", in.Provider, res.Status)
			if res.AccountID != "" {
				fmt.Fprintf(&b, "账号: %s\n", res.AccountID)
			}
			if res.Arn != "" {
				fmt.Fprintf(&b, "身份: %s\n", res.Arn)
			}
			if res.Message != "" {
				fmt.Fprintf(&b, "结论: %s\n", res.Message)
			}
			return actool.Text(b.String()), nil
		},
	})
}

// toolCredVerifyDB 数据库凭据实连(postgres/redis)。
func (s *Server) toolCredVerifyDB() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "credential_verify_db",
		Description: "数据库凭据实连验证(只读):postgres(pgx 实连+current_user/版本/权限面)与 redis(裸协议 PING/AUTH/INFO," +
			"无密码可达即未授权访问)。mysql/mongo 未支持会明确报错。返回存活性与权限面结论,不做任何写操作。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"type":     map[string]any{"type": "string", "description": "postgres|redis"},
				"host":     map[string]any{"type": "string"},
				"port":     map[string]any{"type": "integer"},
				"username": map[string]any{"type": "string"},
				"password": map[string]any{"type": "string"},
				"database": map[string]any{"type": "string", "description": "postgres 可选(默认 postgres)"},
			},
			"required": []string{"type", "host"},
		},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision { return actool.Allowed() },
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in creds.DBProbeInput
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if msg := s.credsRoE(ctx, in.Host); msg != "" {
				return actool.Errorf(msg), nil
			}
			res, err := creds.VerifyDB(ctx, in)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "%s\n", res.Detail)
			if res.Alive && !res.Authed {
				b.WriteString("(服务可达,凭据未通过——弱口令字典可换候选重试)\n")
			}
			// 验证成功且确实提供了口令 → 自动落连接台账(项目上下文时)。
			// 空口令不能算"已验证凭据":开放实例无需认证,存空 secret 只会让
			// 台账显示一条无法复用的假记录(目标后续开启 requirepass 就会失效)。
			if res.Alive && res.Authed && strings.TrimSpace(in.Password) == "" {
				b.WriteString("(服务可达且无需认证——未授权访问;未写入连接台账)\n")
			}
			if res.Alive && res.Authed && strings.TrimSpace(in.Password) != "" {
				note := s.autoCaptureConnection(ctx, &db.Connection{
					Kind: strings.ToLower(strings.TrimSpace(in.Type)), Host: in.Host, Port: in.Port,
					Username: in.Username, Secret: in.Password, Status: "alive",
					Note: "credential_verify_db 验证成功",
				})
				if note != "" {
					b.WriteString(note + "\n")
				}
			}
			return actool.Text(b.String()), nil
		},
	})
}

// toolCredVerifySSH SSH 凭据实连(登录+id+sudo -n 只读探测)。
func (s *Server) toolCredVerifySSH() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "credential_verify_ssh",
		Description: "SSH 凭据实连验证(只读):x/crypto/ssh 建连认证,成功后 id 摸用户组、sudo -n true 摸免密 sudo(高危)。" +
			"密码或私钥二选一。不做任何写操作。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"host":        map[string]any{"type": "string"},
				"port":        map[string]any{"type": "integer"},
				"username":    map[string]any{"type": "string"},
				"password":    map[string]any{"type": "string"},
				"private_key": map[string]any{"type": "string", "description": "PEM 私钥(与 password 二选一)"},
			},
			"required": []string{"host", "username"},
		},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision { return actool.Allowed() },
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in creds.SSHProbeInput
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if msg := s.credsRoE(ctx, in.Host); msg != "" {
				return actool.Errorf(msg), nil
			}
			res, err := creds.VerifySSH(ctx, in)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "%s\n", res.Detail)
			// 验证成功且确实提供了凭据 → 自动落连接台账(项目上下文时)。
			secret := in.Password
			if secret == "" {
				secret = in.PrivateKey
			}
			if res.Alive && res.Authed && strings.TrimSpace(secret) != "" {
				note := s.autoCaptureConnection(ctx, &db.Connection{
					Kind: "ssh", Host: in.Host, Port: in.Port,
					Username: in.Username, Secret: secret, Status: "alive",
					Note: "credential_verify_ssh 验证成功",
				})
				if note != "" {
					b.WriteString(note + "\n")
				}
			}
			if res.Authed {
				if res.User != "" {
					fmt.Fprintf(&b, "用户: %s\n", res.User)
				}
				if res.Groups != "" {
					fmt.Fprintf(&b, "身份: %s\n", res.Groups)
				}
				if res.SudoNOPW {
					b.WriteString("免密 sudo: 是(高危,可直接提权)\n")
				}
			}
			return actool.Text(b.String()), nil
		},
	})
}

// toolGithubDork GitHub 泄露 dork 搜索。
func (s *Server) toolGithubDork() actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: "github_dork",
		Description: "GitHub 代码泄露搜索(需 GitHub Token,系统设置→空间测绘页同区或 GITHUB_TOKEN 环境变量):" +
			"内置 dork 模板(邮箱后缀/API key 特征/密码变量/配置文件等)按组织/域名检索泄露,返回命中片段与仓库线索。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"template": map[string]any{"type": "string", "description": "dork 模板 id(缺省=列出全部模板)"},
				"org":      map[string]any{"type": "string", "description": "GitHub 组织/用户名"},
				"domain":   map[string]any{"type": "string", "description": "目标域名(邮箱后缀方向)"},
				"query":    map[string]any{"type": "string", "description": "自定义查询(覆盖模板)"},
				"limit":    map[string]any{"type": "integer", "description": "返回条数(默认 10)"},
			},
		},
		ReadOnly:    func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, actool.Context) actool.Decision { return actool.Allowed() },
		Run: func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			var in struct {
				Template string `json:"template"`
				Org      string `json:"org"`
				Domain   string `json:"domain"`
				Query    string `json:"query"`
				Limit    int    `json:"limit"`
			}
			if err := json.Unmarshal(input, &in); err != nil {
				return actool.Errorf("参数解析失败: " + err.Error()), nil
			}
			if in.Limit <= 0 {
				in.Limit = 10
			}
			// 无 template 且无 query:列出模板清单(能力自描述)。
			if strings.TrimSpace(in.Template) == "" && strings.TrimSpace(in.Query) == "" {
				var b strings.Builder
				b.WriteString("dork 模板:\n")
				for _, t := range creds.Templates() {
					fmt.Fprintf(&b, "- %s [%s] %s\n", t.ID, t.Category, t.Title)
				}
				return actool.Text(b.String()), nil
			}
			query := strings.TrimSpace(in.Query)
			if query == "" {
				t, ok := creds.TemplateByID(in.Template)
				if !ok {
					return actool.Errorf("模板不存在: " + in.Template), nil
				}
				query = creds.BuildQuery(t, in.Org, in.Domain)
			}
			client := s.githubDorkClient()
			result, err := client.Search(ctx, query, 1, in.Limit)
			if err != nil {
				return actool.Errorf(err.Error()), nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "查询 %q:总命中 %d,返回 %d\n", query, result.TotalCount, len(result.Items))
			for _, h := range result.Items {
				fmt.Fprintf(&b, "- %s (%s)\n", h.Path, h.Repo)
				for _, fr := range h.Fragments {
					fmt.Fprintf(&b, "  %s\n", strings.TrimSpace(fr))
				}
			}
			b.WriteString("\n命中线索建议登记为 finding 证据并通知资产方轮换。")
			return actool.Text(b.String()), nil
		},
	})
}

// credTools 凭据验证工具族。
func (s *Server) credTools() []actool.CoreTool {
	return []actool.CoreTool{
		s.toolCredVerifyCloud(),
		s.toolCredVerifyDB(),
		s.toolCredVerifySSH(),
		s.toolGithubDork(),
	}
}
