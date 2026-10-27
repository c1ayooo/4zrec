package github

import "strings"

// DorkTemplate is one reusable GitHub code-search query.
type DorkTemplate struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Title    string `json:"title"`
	Query    string `json:"query"`
	Note     string `json:"note,omitempty"`
}

var dorkLibrary = []DorkTemplate{
	// ── 云厂商密钥（前缀词直接搜） ──
	{ID: "aws-key-env", Category: "云厂商密钥", Title: "AWS Access Key（env/yaml 文件）", Query: `AKIA extension:env`, Note: "AWK 前缀本身够特异，加文件类型减少噪音；可叠加 -extension:md"},
	{ID: "aws-key-yaml", Category: "云厂商密钥", Title: "AWS Access Key（yaml 文件）", Query: `AKIA extension:yaml`},
	{ID: "aliyun-key", Category: "云厂商密钥", Title: "阿里云 AccessKey", Query: `LTAI`},
	{ID: "tencent-key", Category: "云厂商密钥", Title: "腾讯云 SecretId", Query: `AKID`},
	{ID: "ks3-key", Category: "云厂商密钥", Title: "金山云 KS3", Query: `AKLT extension:yaml`},
	{ID: "qiniu-key", Category: "云厂商密钥", Title: "七牛密钥", Query: `QiNiuSecKey extension:toml`},
	{ID: "aws-key-pair", Category: "云厂商密钥", Title: "AWS 密钥对同现", Query: `AKIA "secret_access_key"`, Note: "代码里通常写成一对，命中即高危"},
	{ID: "aws-key-clean", Category: "云厂商密钥", Title: "AWS 密钥对（降噪）", Query: `AKIA "aws_secret_access_key" -extension:po -extension:md`, Note: "密钥对同现 + 排除翻译/文档，信噪比远高于裸 AKIA"},

	// ── 文件名定向（命中率最高） ──
	{ID: "config-toml-password", Category: "文件名定向", Title: "config.toml 中的密码", Query: `filename:config.toml password`},
	{ID: "config-toml-redis", Category: "文件名定向", Title: "config.toml 中的 Redis 配置", Query: `filename:config.toml redis`},
	{ID: "config-yml-secret", Category: "文件名定向", Title: "config.yml 中的 secret", Query: `filename:config.yml secret`},
	{ID: "config-yaml-apikey", Category: "文件名定向", Title: "config.yaml 中的 api_key", Query: `filename:config.yaml "api_key"`},
	{ID: "spring-datasource", Category: "文件名定向", Title: "Spring 数据源密码", Query: `filename:application.yml "datasource" password`, Note: "Java Spring 配置常堆密码"},
	{ID: "django-secret", Category: "文件名定向", Title: "Django SECRET_KEY", Query: `filename:settings.py SECRET_KEY`, Note: "Django 经典泄露"},
	{ID: "env-db-password", Category: "文件名定向", Title: ".env 数据库密码", Query: `filename:.env DB_PASSWORD`},
	{ID: "npmrc-token", Category: "文件名定向", Title: ".npmrc 发布 token", Query: `filename:.npmrc _authToken`},
	{ID: "pypirc-password", Category: "文件名定向", Title: ".pypirc 密码", Query: `filename:.pypirc password`},
	{ID: "gcp-credentials", Category: "文件名定向", Title: "GCP 服务账号", Query: `filename:credentials.json`, Note: "命中即高危"},
	{ID: "id-rsa", Category: "文件名定向", Title: "SSH 私钥入库", Query: `filename:id_rsa`},
	{ID: "config-json-secret", Category: "文件名定向", Title: "config.json 客户端密钥", Query: `filename:config.json "client_secret"`},

	// ── 服务指纹 ──
	{ID: "etcd-endpoint", Category: "服务指纹", Title: "etcd 端点泄露", Query: `filename:config.toml etcd_endpoint`},
	{ID: "redis-requirepass", Category: "服务指纹", Title: "Redis 密码", Query: `extension:conf requirepass`},
	{ID: "mongodb-conn", Category: "服务指纹", Title: "MongoDB 连接串", Query: `extension:yaml "mongodb://" password`},
	{ID: "ftp-password", Category: "服务指纹", Title: "FTP 密码", Query: `filename:config "ftp" password`, Note: "filename: 是子串匹配，config* 无需星号"},
	{ID: "smtp-password", Category: "服务指纹", Title: "SMTP 密码", Query: `extension:yaml smtp_password`},
	{ID: "jwt-secret", Category: "服务指纹", Title: "JWT secret", Query: `extension:yaml "jwt" secret`},
	{ID: "mysql-conn-js", Category: "服务指纹", Title: "MySQL 连接（JS）", Query: `extension:js "mysql://" password`},
	{ID: "mysqli-php", Category: "服务指纹", Title: "MySQL 连接（PHP）", Query: `extension:php "mysqli_connect" password`},
	{ID: "intranet-etcd", Category: "服务指纹", Title: "内网 IP 特征（etcd）", Query: `extension:toml "etcd" "10.1"`},
	{ID: "intranet-redis", Category: "服务指纹", Title: "内网 IP 特征（Redis）", Query: `extension:yaml "redis" "172.16"`},

	// ── 私钥块（内容指纹） ──
	{ID: "rsa-key", Category: "私钥块", Title: "RSA 私钥", Query: `"BEGIN RSA PRIVATE KEY" -extension:md`, Note: "md 里多是演示"},
	{ID: "openssh-key", Category: "私钥块", Title: "OpenSSH 私钥", Query: `"BEGIN OPENSSH PRIVATE KEY"`},
	{ID: "ec-key", Category: "私钥块", Title: "EC 私钥", Query: `"BEGIN EC PRIVATE KEY"`},
	{ID: "pem-key", Category: "私钥块", Title: "PEM 私钥", Query: `extension:pem "PRIVATE KEY"`},

	// ── org 定向（{org} 占位） ──
	{ID: "org-aws", Category: "org 定向", Title: "目标 org 的 AWS 密钥", Query: `org:{org} AKIA`},
	{ID: "org-env", Category: "org 定向", Title: "目标 org 的 .env", Query: `org:{org} filename:.env`},
	{ID: "org-apikey", Category: "org 定向", Title: "目标 org 的 api_key", Query: `org:{org} "api_key"`},
	{ID: "org-secret-json", Category: "org 定向", Title: "目标域名 secret_key（JSON）", Query: `"{domain}" "secret_key" extension:json`},
	{ID: "org-config-php", Category: "org 定向", Title: "目标域名 config.php", Query: `"{domain}" filename:config.php`},
}

// Templates returns a copy of the built-in dork library.
func Templates() []DorkTemplate {
	out := make([]DorkTemplate, len(dorkLibrary))
	copy(out, dorkLibrary)
	return out
}

// TemplateByID returns one template by ID.
func TemplateByID(id string) (DorkTemplate, bool) {
	for _, t := range dorkLibrary {
		if t.ID == id {
			return t, true
		}
	}
	return DorkTemplate{}, false
}

// BuildQuery substitutes {org} and {domain} placeholders.
func BuildQuery(t DorkTemplate, org, domain string) string {
	q := t.Query
	if org != "" {
		q = strings.ReplaceAll(q, "{org}", org)
	}
	if domain != "" {
		q = strings.ReplaceAll(q, "{domain}", domain)
	}
	return q
}
