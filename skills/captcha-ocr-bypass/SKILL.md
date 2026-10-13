---
name: captcha-ocr-bypass
description: >-
  验证码绕过:ddddocr OCR 识别,算式验证码解析,万能码,验证码不刷新复用,前端校验绕过/改返回包,短信码爆破与竞态,频控绕过。Use when login or business flows are gated by captcha/OTP and you need automated or logic-flaw based bypass within an authorized test.
metadata:
  roles: [渗透测试, Web与API安全测试]
  stages: [web, api]
  tags: [渗透测试, penetration-testing, 红队]
---

## 验证码绕过 / OCR

```
=== captcha bypass ===
OCR 识别: 平台工具 ddddocr 直接识别图形码 | 预处理(灰度/二值化/去噪)后再识别提准确率 | 打码平台兜底
算式验证码: 正则提取 "3+5=?" / "最大值" 类题面 → 计算后提交
万能码/通用码: 0000 8888 1234 aa bb (测试环境遗留后门) | 图形码 4 位全字码
复用类: 验证码不销毁→同码多次提交 | 只校验非空→任意值过 | 返回包携带验证码→响应里直接读
前端校验绕过: 删 captcha 参数/置空 | 改返回包 false→true 再放包(响应 hack) | 校验逻辑全在前端 JS
短信/邮箱码: 4-6 位纯数字且接口不限速→并发爆破(先看频控) | 万能验证码/固定码 | 竞态:验证码校验与销毁非原子→并发多请求复用一次
频控绕过: 换 IP/账号/设备指纹重置计数 | 时间窗滑动 | 分批慢速
纪律: 仅用于授权测试的登录/业务流程;不绕生产风控做真实资损,爆破类先确认接口速率限制
```

## 平台工具操作序列（browser_interact，登录墙不是死路）

```
字符验证码: browser_interact {"action":"screenshot"} 拿验证码图 → ddddocr 识别
  → {"action":"type","selector":"input[name=code]","value":"识别结果"} → {"action":"submit"}
  识别错就重截图重识别(验证码会刷新)
滑块: screenshot 看缺口位置估算距离 → {"action":"drag","selector":".slider-btn 等把手选择器","value":"600"}
  (拟人轨迹自动) 失败换距离重试 2-3 次,仍不过记 attempt(blocked)换路
登录态: 交互后用 browser_interact 返回的「交互触发的接口」继续 http_probe 重放测试;
  登录态 Cookie 会随会话保留,后续请求可复用
```
