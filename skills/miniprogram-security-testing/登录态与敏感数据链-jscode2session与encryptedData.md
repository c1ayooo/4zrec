# 登录态与敏感数据链：jscode2session 与 encryptedData

微信小程序最高频高危链：包内泄露的 AppID/AppSecret → 换 session_key → 解密 sensitiveData 得手机号/unionId → 伪造身份越权。平台工具：`miniapp_verify`（凭据验真）→ `miniprogram_jscode2session`（换登录态）→ `miniprogram_decrypt_userdata`（解密）。

## 第一步：凭据验真与换取登录态

```
GET https://api.weixin.qq.com/sns/jscode2session
    ?appid=APPID&secret=SECRET&js_code=JSCODE&grant_type=authorization_code
成功: {"openid":"oXyz...","session_key":"iWGx...","unionid":"uAbc..."}
```

- `js_code` 来自小程序端 `wx.login()`：一次性、约 5 分钟有效，从抓包流量提取或用户配合获取。
- **实测结论（2026-09-19）**：jscode2session 不受 cgi-bin 的 IP 白名单约束——同一对 AppID/Secret 调 `/cgi-bin/token` 报 40164（IP 不在白名单）时，jscode2session 仍正常校验凭据。泄露的 Secret 应视为已失陷，白名单不是缓解措施。
- 错误码语义：
  - `40029` invalid code：**凭据已通过微信校验**（appid+secret 正确），仅 js_code 无效/已使用/过期——凭据旁路验证通过，换新 code 即可换到 session_key
  - `40125` / `40001`：AppSecret 错误；`40013`：AppID 不存在
  - `40164`：出口 IP 被拒（该接口出现此码说明目标强制了白名单，属罕见路径）
  - `45011`：频率限制；`40226`：微信判定高风险用户拒绝
- 凭据验证还可先用 `miniapp_verify`（走 cgi-bin/token，结论四档：valid/invalid/restricted/unverifiable；restricted=AppID 真实存在但出口 IP 不在白名单，secret 未核验，仍是强信号）。

## 第二步：encryptedData 解密（sensitiveData）

`wx.getUserInfo`、`getPhoneNumber`（旧版）等返回 `encryptedData + iv`，用 session_key 解密：

1. `session_key`、`encryptedData`、`iv` 均为标准 base64；session_key 解码后 16 字节（AES-128 密钥），iv 16 字节。
2. AES-128-CBC 解密，PKCS#7 去填充，明文为 JSON。
3. 明文含 `watermark: {appid, timestamp}`：**水印 appid 与目标小程序不一致 = session_key 跨小程序混用**，数据不可作证据。

典型明文结构：

- 手机号链：`{"phoneNumber":"138...","purePhoneNumber":"138...","countryCode":"86","watermark":{...}}`
- 用户信息链：`{"nickName":"...","unionId":"...","openId":"...","watermark":{...}}`

注意版本差异：新版手机号获取走 `POST /wxa/business/getuserphonenumber?access_token=`（服务端接口换取，code 来自 button open-type=getPhoneNumber），不解 encryptedData。两条链在后端落地手机号时都要看唯一性校验（改 countryCode 变体绕过一号一号制）。

## 第三步：会话伪造与越权验证（主动利用，须显式授权）

典型后端模式：code2session 得 openid → 用 openid 查/建用户 → 签发自建 token。薄弱点：

- 请求参数或 token payload 直接携带 openid/userId → 改他人标识即横向越权
- 登录接口信任客户端传的 openid（服务端不回查）→ 直接伪造身份注册/登录他人账号
- session_key 下发给前端 → 前端可自行解密并篡改 unionId 绑定链路

验证方法：`http_session` 维持 A/B 双账号会话，A 的请求替换 B 的资源标识重放比对；最小化验证（一条他人数据即止），不批量拉取。

## 报告纪律

- 「接口可用性」（能换到 session_key、能解密数据）与「是否伪造他人身份」（主动越权）分开表述；后者仅在授权范围显式允许时执行。
- session_key/openid/手机号不整串粘贴进报告；手机号写形态（138****0000）。
