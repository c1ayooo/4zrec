---
name: sso-cas-ticket-abuse
description: >-
  SSO/CAS 票据滥用与认证入口不对称:门户接入系统枚举,三跳票据链验证,service 参数篡改,ST/ticket 重放,持票直达后台,直连被拒不等于 SSO 进不去。Use when a target uses CAS/SSO/统一认证 (ticket=, service=, cas/, sso/, portal paths or 统一认证 wording), or when direct login to an integrated system fails but the SSO-fed jump may still grant an authenticated backend session.
metadata:
  roles: [Web与API安全测试, 渗透测试]
  stages: [web, api]
  tags: [渗透测试, penetration-testing, SSO, CAS, 认证, 红队]
---

## SSO/CAS 票据滥用与认证入口不对称

```
=== 信号识别 ===
ticket=/ST-/TGT-/LT- 参数或值 | /cas/ /sso/ /portal/ /统一认证 路径与措辞 | service=/TARGET=/renew= 参数 | SAMLRequest/SAMLResponse | authorize?redirect_uri= | 登录页含「统一身份认证/单点登录」字样
=== 入口不对称（核心场景）===
直连独立登录页 403/无本地账号/弱口令失败 ≠ 测完——接入系统信任 IdP 发的会话，持票跳转可能直接进后台
1. 门户枚举:有 SSO 会话先解析门户/工作台全部业务系统链接登记为 seed(很多系统只有门户跳转可达);
   无账号试匿名门户/未授权接口拿接入系统清单(配 /docs 首页/JS 素材交叉)
2. 三跳链逐跳验证(不跟随重定向,单请求不下结论):
   第1跳 GET 业务系统:200 有登录态=直通;302 指向认证域(带 service/redirect)=SSO 接入;独立登录页=独立认证
   第2跳 带 IdP 会话 GET 认证 URL:302 回带 ticket=会话有效可发票据;仍登录页=对该系统无效,记录不重试
   第3跳 GET ticket 回跳地址:200/Set-Cookie 即进入,保存业务会话
3. 判定矩阵落 Fact(系统 × 判定[直通/SSO接入-有效/无效/独立] × 跳转链证据);判定有效必须继续完整测后台,
   「跳转进去了」不等于「测过了」:后台路由直奔(/admin/console/manage,来源=JS 提取/字典)、菜单隐藏接口、
   权限只校验「有会话」不校验「有角色」即越权
4. 直连失败的系统必须再走 SSO 跳转测一遍(本地无账号≠域账号不可用);反向同理,直连通了也要验票据链完整性
=== 票据滥用 ===
service 篡改:申请票据处改 service= 指向其他接入系统/后台路径(发证端不校验 service 白名单即跨系统发证)
ST 重放:CAS ST 设计一次性——同 ticket 二次用/换 IP 用/过期窗口外仍验通过=校验实现缺陷
会话不绑定:登出/吊销后 ticket 仍可换会话 | 匿名/未完成认证即发放 ticket | renew=true 强认证要求可绕
回调宽松:service/redirect_uri 白名单子域/路径/URL 编码变形(配 path-403-bypass 的变形思路)→ 票据带出授权域
=== 纪律 ===
三跳逐跳存证(请求响应原样落证据);票据只对授权范围内系统测试;不重放他人票据、不做真锁号;
每系统结论进 SSO 覆盖矩阵,负结果也记(无效/独立认证是后续横向的地图)
```
