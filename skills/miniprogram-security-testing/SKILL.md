---
name: miniprogram-security-testing
description: "小程序安全测试专业技能（微信/支付宝/多端）：wxapkg 解包与 V1MMWX 加密包解密、分包/插件/WASM 还原、静态审计（签名/加密/防重放）、登录态与敏感数据链（jscode2session 换 session_key、encryptedData AES-128-CBC 解密手机号/unionId）、伪造 openid 越权验证、云开发 CloudBase 专测（云函数未授权/集合权限矩阵）、web-view/JSBridge/小程序码 scene 注入、支付逻辑、测试项账本闭环。"
version: 1.0.0
tags: [miniprogram, wechat, wxapkg, jscode2session, session_key, encrypteddata, cloudbase, 越权, 支付, 小程序]
metadata:
  roles: [小程序安全测试]
  stages: [miniprogram]
---

# 小程序安全测试（miniprogram-security-testing）

## 概述

小程序（WeChat/Alipay/抖音等）是「前端包 + 平台运行时 + 后端接口 + 云开发」的复合体。它的攻击面主线：

1. **包**：wxapkg 可解包还原出全部前端源码——接口、密钥、签名算法、业务逻辑全部可见（相当于把 Web 的前端审计做透）。
2. **登录态与敏感数据链**：AppID/Secret + js_code 换 session_key，再解密 sensitiveData 拿手机号/unionId——小程序最高频的高危链，一旦包内泄露 Secret 即可整链打通。
3. **接口**：与 Web API 相同的未授权/越权/注入面，但鉴权常用自实现的签名+登录态，薄弱点更多。
4. **云开发（CloudBase）**：云函数未授权直调、云数据库集合权限配错即全局可读写他人数据。

**方法论骨架（六阶段）**：阶段0 取包与来源判定 → 阶段1 解包与还原 → 阶段2 静态审计 → 阶段3 登录态与敏感数据链 → 阶段4 接口与业务 → 阶段5 客户端攻击面 → 阶段6 报告与销账。每个阶段都能落到平台工具，发现逐项进测试项账本（miniprogram_test_items / miniprogram_test_item_update）闭环。

**专项深化参考（同目录伴随文件，按需读全文，不必一次全载）**：
- `wxapkg解包与加密包解密.md`——阶段1 深化：V1MMWX 加密包解密细节与分包还原
- `登录态与敏感数据链-jscode2session与encryptedData.md`——阶段3 深化：整链复现与伪造 openid 越权验证
- `接口与业务逻辑测试-签名越权支付.md`——阶段4 深化：签名逆向、越权矩阵、支付状态机
- `云开发CloudBase安全测试.md`——CloudBase 专测：云函数未授权与集合权限矩阵
- `客户端攻击面-webview与JSBridge与小程序码.md`——阶段5 深化：web-view/JSBridge/scene 注入
- `跨平台小程序与包内容覆盖边界.md`——支付宝/抖音/uniapp 多端差异与覆盖边界
- `小程序安全测试检查清单.md`——收口用全量检查清单（阶段6）

**授权边界（硬约束，优先于一切技巧）**：仅测试已授权目标；登录态伪造/越权验证是主动利用动作，必须人工/显式触发并遵守 ROE；不批量拉取用户数据（openid 清单、手机号、地址）；支付测试用最小金额自建订单，不碰真实交易；session_key、手机号、openid 不得整串粘贴进报告。

## 一、平台工具链映射（先用平台，再补外部）

| 阶段 | 平台工具 | 说明 |
| --- | --- | --- |
| 取包 | `miniprogram_pc_fetch` | PC 微信缓存直取（scan/harvest，WSL/Windows 免 root，4.x radium 与 3.x Applet 布局都扫，加密包按目录名 appid 自动解密） |
| 取包 | `android_device_miniprogram` | root 真机直取微信私有目录 wxapkg（scan/harvest 同款交互） |
| 解包+首扫 | `miniprogram_analyze` | 上传 wxapkg → 解析/解密/分包合并 → 敏感信息扫描 → 生成测试项账本。PC 微信 4.x 加密包必须带 appid |
| 源码审计 | `miniprogram_source` / `miniprogram_findrefs` | 读单文件 / 跨文件关键词正则搜索 |
| 账本 | `miniprogram_test_items` / `miniprogram_test_item_update` | 拉取扫描生成的待验证清单；逐项验证后回写 confirmed/clean/na + 结论 + 证据 |
| 登录态链 | `miniapp_verify` | AppID/Secret 有效性（cgi-bin/token；40164=AppID 真实但出口 IP 受限，仍是强信号） |
| 登录态链 | `miniprogram_jscode2session` | js_code 换 openid/session_key/unionid（**不受 IP 白名单约束**；code_invalid=凭据旁路验证通过）；credential_id 可复用凭证池 |
| 登录态链 | `miniprogram_decrypt_userdata` | session_key+encryptedData+iv → AES-128-CBC 解密（手机号/unionId），自动校验 watermark.appid |
| 接口 | `http_probe` / `http_session` / `http-framework-test` | 重放测未授权 / 保登录态做越权 / 参数篡改 |
| 注入/JWT | `sqlmap` / `dalfox` / `jwt-analyzer` | 接口注入与 JWT 算法混淆 |
| 凭据验证 | `cloud_key_verify` / `llm_key_verify` | 包内发现的云 AK/SK、模型 Key 当场最小化验证 |
| 收尾 | `record_vulnerability` / `save_evidence` / `upsert_project_fact` | 漏洞落库 / 取证 / 项目事实 |
| 结构 | `miniprogram_structure` | 包结构报告:路由/分包/插件/Worker/WASM/开放数据域/web-view 落地域名 + 覆盖边界提示 |
| 云开发 | `miniprogram_cloudbase` | 云开发资产盘点(env/云函数/集合/fileID/匿名痕迹) + 逐资产生成测试项进账本 |
| 动态调试 | `miniprogram_devtools` | CDP 连开发者工具/PC 微信调试端口:目标枚举/任意 JS 求值/wx.request hook/storage 导出/页面栈快照 |

知识检索：`search_knowledge_base` 用 `risk_type=小程序安全测试` 过滤本板块知识条目；`search_skill_library` 检索历史技能与 PoC。平台能力不可用时才转外部工具（unveilr/wxappUnpacker、prettier/js-beautify 还原压缩 JS）。

## 二、阶段0：取包与来源判定

渠道按成本排序：

1. **PC 微信缓存直取**（最便宜）：Windows 微信打开过目标小程序即有缓存。
   - 微信 4.x（radium 新架构）：`<用户目录>/AppData/Roaming/Tencent/xwechat/radium/users/<账号>/applet/packages/<appid>/<版本>/__APP__.wxapkg`（+ `_subpackages_*.wxapkg`）
   - 微信 3.x（旧架构）：`<用户目录>/Documents/WeChat Files/Applet/<appid>/<hash>/*.wxapkg`
   - WSL 部署下 `/mnt/<盘>/Users/...` 直接可读，无需 root。**AppID 就是包目录名**——V1MMWX 解密的必要入参。
2. **Android root 直取**：`android_device_miniprogram`（前提：手机微信打开过目标小程序）。
3. **上传**：用户提供 wxapkg；PC 微信 4.x 的加密包必须同时提供 AppID，缺 AppID 时平台会把包挂起待补（miniprogram_analyze 报错文案会提示）。

来源判定：先看包是否加密（V1MMWX 前缀）、主包还是分包（分包单独上传会缺 app.json）、PC 4.x 还是移动端包——这决定解密入参与合并策略。

## 三、阶段1：解包与还原

### 3.1 wxapkg 格式（实测确认）

```
偏移 0      1B    起始标记 0xBE
偏移 1-4    4B    info1（大端，恒 0）
偏移 5-8    4B    索引区长度（大端）
偏移 9-12   4B    数据区长度（大端）
偏移 13     1B    结束标记 0xED
偏移 14-17  4B    文件数量（大端）
偏移 18+    条目：[4B 名长][N 名][4B 偏移][4B 大小]×N → 数据区
```

### 3.2 V1MMWX 加密包解密（PC 微信 4.x）

- 前 6 字节为 `V1MMWX` 魔数。
- **前 1024 字节**：AES-256-CBC，key = PBKDF2-HMAC-SHA1(appid, "saltiest", 1000, 32)，IV = `"the iv: 16 bytes"`（字面量）。
- **其余字节**：逐字节 XOR appid 倒数第 2 个字符。
- 明文 = 前 1023 字节（第 1024 字节是占位）‖ 解出的尾部。
- 平台已内置（`miniprogram_analyze` 带 appid 自动解密），手写脚本时注意 PBKDF2 迭代 1000 次、输出 32 字节。

### 3.3 还原要点

- **分包合并**：主包 + `_subpackages_*`，同名路径后包覆盖先包——覆盖清单本身就是线索（「隐蔽覆盖」常藏逻辑）。平台多包一次上传自动合并并返回被覆盖清单。
- **app.json**：pages 路由、subpackages、plugins（`plugin://`）、permission、requiredBackgroundModes——攻击面地图。
- 常缺的部分：**插件**、**Worker**（`workers/`）、**WASM**（wxwebassembly）、**开放数据域**（子域包）——平台当前不解这些，findrefs 搜不到时要意识到覆盖边界，必要时手工 unpack。
- 压缩 JS 可读化：node + prettier/js-beautify 格式化后再审。
- `miniprogram_structure` 一次产出结构报告（路由/分包/插件/Worker/WASM/开放数据域/web-view 域名 + 覆盖边界提示）——审计开局先跑它建立攻击面地图。

## 四、阶段2：静态审计

按优先级：

1. **敏感信息**：appid/AppSecret（`miniprogram_findrefs` 搜 `appsecret|secret`）、access_token、云开发 env、OSS/AK/SK、内网域名、第三方支付商户号、JWT secret。发现的密钥当场走 `cloud_key_verify`/`miniapp_verify`/`llm_key_verify` 验真并入凭证池。
2. **请求封装层**：找统一 request 包装（搜 `wx.request`、自定义 `request(`、拦截器），提取：鉴权头、**签名算法**（参数排序+盐+MD5/HMAC）、**加密逻辑**（AES key 常硬编码或由 appid 派生）、时间戳/nonce 防重放字段。签名与加密函数要在阶段4 用 node 复现。
3. **登录态处理**：`wx.login` → code 的去向、`wx.checkSession`、token 存储位置（storage key）、openid 是否被前端参与鉴权计算（可篡改信号）。
4. **跳转面**：`navigateTo/redirectTo` 的 URL 来源、`web-view` 的 src 是否可污染（任意跳转 → 阶段5）。
5. **支付与业务逻辑**：支付金额是否前端计算、限购/风控判断是否纯前端（`if (count > limit)` 直接改）。

## 五、阶段3：登录态与敏感数据链（最高价值环节）

### 5.1 jscode2session 换取登录态

```
GET https://api.weixin.qq.com/sns/jscode2session
    ?appid=APPID&secret=SECRET&js_code=JSCODE&grant_type=authorization_code
→ {"openid":"...","session_key":"...","unionid":"..."}
```

- `js_code` 来自小程序端 `wx.login()`：一次性、约 5 分钟有效，从抓包流量里提取，或让用户配合取一次。
- **关键实测结论（2026-09-19）**：该接口**不受 cgi-bin 的 IP 白名单约束**——同一对凭据在 `/cgi-bin/token` 报 40164（IP 不在白名单）时，jscode2session 仍正常校验。因此它是比 miniapp_verify 更强的凭据验证通道。
- 错误码语义（平台的分级）：
  - `40029` invalid code → **凭据已通过微信校验**（appid+secret 正确），仅 code 不可用 = 凭据旁路验证通过（平台状态 `code_invalid`）
  - `40125`/`40001` → secret 错误；`40013` → appid 不存在
  - `40164` → 出现即说明目标强制了 IP 白名单（罕见路径）；`45011` 频率限制；`40226` 高风险拦截
- 报告纪律：「接口可用性」（能换到 session_key）与「是否伪造他人身份」（用伪造 openid 建会话）必须分开表述，后者仅在授权范围显式允许时执行。

### 5.2 sensitiveData 解密（encryptedData）

`wx.getUserInfo`/`getPhoneNumber` 等返回 `encryptedData + iv`，用 session_key 解：

- 三者均标准 base64；**AES-128-CBC**（key = session_key 的 16 字节明文形式，iv 16 字节），PKCS#7 去填充，明文是 JSON。
- 明文带 `watermark: {appid, timestamp}`——**水印 appid 与目标不一致说明 session_key 跨小程序混用**，不能作为证据。
- 典型明文：手机号链 `{phoneNumber, purePhoneNumber, countryCode, watermark}`；用户信息链 `{nickName, unionId, openId, watermark}`。
- 平台工具：`miniprogram_decrypt_userdata`（自动做水印校验）。
- 注意：新版手机号获取（`phonenumber.getPhoneNumber`）走 access_token + 接口换取，不解 encryptedData；两条链都要看后端怎么落地手机号与唯一性校验（改 countryCode/+86 变体绕过一号一号制是常见逻辑洞）。

### 5.3 会话伪造与越权验证（主动利用，显式触发）

- 后端自建会话常见模式：code2session 后用 openid 换自家 token。若 token 或请求参数里直接携带 openid/userId，则可**横向越权**：改 openid/userId/订单归属访问他人数据。
- 验证方法：`http_session` 维持 A/B 两个账号会话，A 的请求换 B 的资源 ID 重放，比对响应；或用伪造 openid 走一遍登录链观察后端是否无条件信任。
- 边界：最小化验证（一条他人数据即止），不批量拉取；多账号越权矩阵逐格确认后回写账本。

## 六、阶段4：接口与业务

1. **端点提取**：findrefs 搜 `wx.request|request\(|https?://`，汇总 host/path 清单 → `http_probe` 逐个无凭据重放测未授权。
2. **越权**：横向（改 ID/参数）、纵向（普通用户调管理接口）；签名接口先还原算法再改参数。
3. **云函数未授权直调**（见第七节）。
4. **支付链**：金额/数量/优惠是否前端可篡改；订单状态机是否可跳步（未支付→已发货）；回调是否验签；用最小金额自建订单验证，绝不碰真实他人交易。
5. **订阅消息/短信**：验证码可枚举、发送无频控、验证逻辑前端化。
6. **限速**：签到/抽奖/领券接口的批量调用与防重放（timestamp+nonce 是否真校验）。

## 七、云开发（CloudBase）专测

包内发现 `wx.cloud.init({env})` / `cloud.callFunction` 即进入云开发面。先用 `miniprogram_cloudbase` 盘点资产并自动生成测试项（逐函数/逐集合进账本），再按下面展开：

1. **云函数未授权直调**：函数名从包内提取；拿到函数名+env 后，验证是否可从小程序上下文外直接触发（HTTP 触发的云函数常见完全裸奔）；云函数内部是否信任客户端传参（把 userId 当参数传进云函数 = 越权直通车）。
2. **云数据库集合权限**（最高频高危）：三档预设——「所有用户可读」「仅创建者可读写」「所有用户可读写」，配错就是未授权读写他人数据；自定义安全规则要逐条看 `doc._openid` 校验是否完备。
3. **云存储**：云桶文件是否可未授权列举/下载（getTempFileURL 的 fileID 可否伪造遍历）。
4. **env 与票据**：env 标识泄露 + 匿名登录开启 = 直接构造匿名凭据访问云资源；发现的云 AK/SK 走 `cloud_key_verify` 验真。

## 七·补、运行时动态调试（DevTools 通道）

静态推断的替代与验证：`miniprogram_devtools` 连微信开发者工具（设置→安全→服务端口，默认 `http://127.0.0.1:9420`；WSL 连 Windows 宿主用宿主 IP）或 PC 微信小程序模式调试端点。

- `action=targets` 枚举上下文（service/content 是小程序逻辑所在）；`action=hook preset=wx_request` 拦截 wx.request 录制真实请求入参/状态码/响应片段，操作小程序后 `action=read` 取数（clear=true 清空续录）。
- `preset=storage` 全量导出本地缓存（登录态/token 明文）；`preset=page_stack` 页面栈与 query 快照。
- `action=eval` 任意 JS：绕过前端校验（限购/风控/表单约束）、直接调用页面内加密函数观察签名入参、篡改运行时变量——观察到的算法配合 node 复现。
- 边界：运行时注入属主动利用，仅在授权范围内；报告中标注「运行时触发方式」与影响面。

## 八、阶段5：客户端攻击面

- **web-view 任意跳转**：src 可污染 → 跳钓鱼页；业务域名白名单绕过（开放 H5 再跳转）。
- **JSBridge**：web-view 内 H5 经 `wx.miniProgram.postMessage/navigateTo` 与小程序通信——H5 的 XSS 可升级为小程序上下文操作。
- **小程序码/二维码**：scene 参数注入（decodeURIComponent 后进 path/query）；跳转劫持；scene 参数直接进后端查询时测注入与越权。
- **分享链接**：分享 path/query 可伪造，落地页参数污染。
- **组件与开放数据域**：子域数据不可直接伪造给主域，但主域把开放数据当鉴权依据就是逻辑洞。

## 九、阶段6：报告与销账

- 每个发现标注：**页面路径 / 接口 / 参数 / 触发方式**；接口类给完整请求+响应报文。
- 漏洞类型用标准枚举：小程序逻辑缺陷 / 小程序接口未授权 / 小程序任意跳转 / 小程序支付漏洞 / 小程序源码泄露 / 小程序云函数未授权 / 小程序敏感数据泄露。
- 账本闭环：miniprogram_test_items 逐项验证 → miniprogram_test_item_update 回写 confirmed/clean/na + 一句话结论 + 证据摘要；确认漏洞 record_vulnerability 落库，弱信号 upsert_project_fact。
- 敏感字段脱敏：手机号 138\*\*\*\*0000、session_key/openid 不整串粘贴。

## 十、检查清单（速查）

**包**：□ 加密判定与解密 □ 分包覆盖清单 □ 插件/worker/wasm/子域 □ app.json 路由与权限
**审计**：□ AppSecret/密钥验真入池 □ 签名与加密算法还原 □ 防重放字段真校验 □ web-view src 可污染 □ 限购风控前端化
**登录态链**：□ 凭据验真（jscode2session 旁路）□ session_key 换取 □ encryptedData 解密+水印 □ openid 越权（显式授权下）
**接口**：□ 无凭据重放 □ 横向/纵向越权 □ 支付金额/状态机 □ 验证码与频控
**云开发**：□ 资产盘点（miniprogram_cloudbase）□ 函数直调 □ 集合权限矩阵 □ 云存储遍历 □ env 泄露+匿名登录
**动态调试**：□ DevTools 端点连通 □ wx.request hook 录制 □ storage 导出 □ 前端校验运行时绕过
**客户端**：□ 任意跳转 □ scene 注入 □ 分享参数污染 □ JSBridge 升级链

## 十一、修复建议速查

- Secret 泄露：轮换 + 启用 IP 白名单（注意白名单不覆盖 jscode2session，泄露即应视为已失陷）+ 最小权限。
- 登录态链：sensitiveData 只在服务端解密；手机号以服务端 phonenumber 接口为准；会话标识不用 openid 明文，服务端映射。
- 越权：所有资源访问按会话身份服务端鉴权（拒绝信任客户端传参），云开发用安全规则显式校验 `_openid`。
- 支付：金额服务端计算、回调验签、状态机幂等。
- web-view：白名单校验落地页域名，跳转参数服务端校验。

## 十二、注意事项

- 平台自身账号/会话/Token 是运维资产，不是渗透目标——禁止读取、修改、伪造平台凭据。
- 跨平台差异（支付宝 `.tar` 包/`my.*` API、抖音/百度各自包结构）当前平台只内置微信链路，其他端手动适配。
- 所有主动利用（会话伪造、越权、支付篡改）在会话里显式声明授权依据后再动手；无授权依据时只做只读验证（凭据验真、未授权重放探测）并如实报告。
