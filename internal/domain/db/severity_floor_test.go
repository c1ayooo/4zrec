package db

import "testing"

// TestSeverityFloor 钉住从靶场复盘中暴露的两个服务端定级下限：
// 未授权管理员接管、完整 root DB/Redis/邮件/企微凭据泄露不得被 reporter 压价。
func TestSeverityFloor(t *testing.T) {
	cases := []struct {
		name                                string
		vulnclass, title, summary, evidence string
		want                                string
	}{
		{
			name:      "未授权创建管理员账号并接管",
			vulnclass: "认证绕过 / 未授权访问",
			title:     "未授权管理员注册接口导致任意攻击者创建 admin 账号并接管 OA 系统",
			summary:   "无需认证即可创建 role_code=admin 的管理员账号，登录后取得系统最高权限。",
			evidence:  "POST /api/test/admin-register {\"username\":\"hacker1\",\"invite_code\":\"oa-admin-2025\"}\n{\"code\":0,\"message\":\"管理员账号创建成功\"}\n登录返回 role_code: admin",
			want:      SeverityCritical,
		},
		{
			name:      "完整 root DB/Redis/邮件/企微凭据匿名泄露",
			vulnclass: "敏感信息泄露 / 未授权访问",
			title:     "未授权接口 /api/system/config 泄露数据库/Redis/邮箱/企业微信明文凭据",
			summary:   "匿名可读完整系统配置，含 MySQL root、Redis、SMTP、企微 secret。",
			evidence:  `{"mysql_host":"mysql","mysql_user":"root","mysql_password":"123456","redis_host":"redis","redis_password":"123456","mail_password":"mail@2025","wechat_secret":"abcdef123456"}`,
			want:      SeverityCritical,
		},
		{
			name:      "单项凭据泄露至少 high",
			vulnclass: "敏感信息泄露",
			title:     "配置接口泄露邮件密码",
			summary:   "匿名读取 mail_password 明文。",
			evidence:  `{"mail_password":"mail@2025"}`,
			want:      SeverityHigh,
		},
		{
			name:      "仅管理员登录页未授权访问不触发下限",
			vulnclass: "未授权访问",
			title:     "未授权访问管理员登录页",
			summary:   "GET /admin/login 返回 200，仅展示登录表单。",
			evidence:  "HTTP/1.1 200 OK\n<html>管理员登录</html>",
			want:      "",
		},
		{
			name:      "版本号泄露不触发下限",
			vulnclass: "信息泄露",
			title:     "响应头泄露版本号",
			summary:   "Server: nginx/1.24.0，不含业务数据。",
			evidence:  "Server: nginx/1.24.0",
			want:      "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SeverityFloor(tc.vulnclass, tc.title, tc.summary, tc.evidence); got != tc.want {
				t.Fatalf("SeverityFloor = %q, want %q", got, tc.want)
			}
		})
	}
}
