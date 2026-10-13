# 云开发 CloudBase 安全测试

包内出现 `wx.cloud.init({ env: '...' })`、`cloud.callFunction`、`cloudbase` 字样即进入微信云开发攻击面。平台 scanner 能提取云函数名与 env 标识（miniprogram_findrefs 搜 `cloud.callFunction|env`）。

## 云函数

- 未授权直调：云函数名可从包内完整提取；HTTP 触发的云函数（cloud function with HTTP trigger / 侧 WebFunction）常见完全裸奔——直接 POST 函数名对应路径即可调用。
- 云函数内部信任客户端传参是最高频逻辑洞：把 userId/orderId 当参数传入云函数 = 越权直通车。验证时观察云函数是否用 `wxContext.OPENID` 做归属校验，还是信任入参。
- 云函数之间的调用链（cloud.callFunction 嵌套）可能存在仅内网可调的管理函数——枚举函数名规律（admin/internal/debug/test）逐个探测。

## 云数据库集合权限（最高频高危）

小程序云开发的集合权限三档预设：

1. **所有用户可读**：任何登录用户可读全部文档——未授权读他人数据（订单/地址/手机号）。
2. **仅创建者可读写**：预设里相对安全，但云函数侧/自定义规则若漏 `doc._openid === wxContext.OPENID` 校验仍可越权。
3. **所有用户可读写**：全局可读写，等同公开数据库。

自定义安全规则（security rules）要逐条读：`read: true`/`write: true` 的通配规则、`auth.openid == doc._openid` 校验是否覆盖每个集合。测试方法：用 A 账号凭据读/写 B 账号创建的文档（按 docId 遍历或枚举）。

## 云存储

- 云存储 fileID（`cloud://env.bucket/path`）可否伪造遍历：`getTempFileURL` 换取临时链接时校验是否只认归属。
- 上传路径是否用户可控（覆盖他人文件）、临时链接是否可未授权分享。

## env 标识与匿名登录

- env 标识在包内明文（`wx.cloud.init` 处）+ 云开发开启「匿名登录」= 可在平台外构造匿名凭据直接访问云资源（TCB API），等价未授权访问。
- 包内发现的腾讯云 SecretId/SecretKey（AKID 前缀）走 `cloud_key_verify` 验真——云开发密钥往往带 TCB/COS 全权限。

## 测试顺序建议

1. 提取 env + 全部函数名 + 云存储 fileID 模式（findrefs）
2. 云函数直调与传参越权（最小化验证）
3. 集合权限矩阵（A/B 身份逐集合确认）
4. 云存储遍历与上传覆盖
5. 密钥验真入池（cloud_key_verify）
