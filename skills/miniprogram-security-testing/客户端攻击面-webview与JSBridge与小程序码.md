# 小程序客户端攻击面：web-view、JSBridge、小程序码与分享

## web-view 与任意跳转

- `<web-view src="{{url}}">` 的 url 来源若可污染（接口返回、分享参数、scene 拼接），即任意跳转 → 钓鱼/信息收集页。业务域名白名单只约束 web-view 首跳，页面内再跳转不受限——「开放一个可跳转的 H5」就等于绕过白名单。
- 检查点：src 的拼接逻辑（findrefs 搜 `web-view|webview` 与 `navigateTo`）、跳转参数是否服务端校验域名。
- 危害升级链：web-view 加载的 H5 有 XSS → JSBridge 升级。

## JSBridge（wx.miniProgram.*）

- web-view 内 H5 通过 `wx.miniProgram.postMessage / navigateTo / switchTab / getEnv` 与小程序容器通信。
- H5 的 XSS 可升级为小程序上下文操作：postMessage 触发小程序逻辑、navigateTo 携带污染参数进入其他页面。
- 插件（plugin://）同样暴露 JSBridge 接口——插件上下文的信任边界常被忽略。

## 小程序码与 scene 参数

- 小程序码/二维码携带 `page + scene`（scene 为字符串参数，进入 onLoad 的 options.scene，通常 `decodeURIComponent` 后按 key=value 解析）。
- scene 注入：scene 内容进 path/query/后端查询时，测 URL 跳转劫持、注入与越权（scene 带邀请码/订单号/渠道号时逐个篡改）。
- 跳转劫持：他人扫码落地页可否被 scene 指到任意页面/任意参数组合。

## 分享链接与落地参数

- `onShareAppMessage` 的 path/query 可伪造——分享卡片可构造任意落地页+参数组合，配合页面 onLoad 的信任缺陷（把 query 当鉴权依据）即逻辑洞。
- 分享图/标题中的接口地址同样可污染。

## 组件与开放数据域

- 开放数据域（open-data context）是独立子包：主域拿不到子域数据本身，但主域把「子域渲染成功」当业务判断依据即是逻辑洞。
- 组件劫持面：cover-view/native 组件的层级覆盖、button open-type 的授权弹窗伪造（诱导授权）。

## 平台现状与操作

- 角色提示词已写跳转参数注入与 JSBridge；handoff 交接清单（miniprogram 交接 Web 角色）包含 `navigateTo`/`web-view` 检查项。
- 落地动作：findrefs 定位可污染源 → http_probe/http_session 验证跳转与参数行为 → 发现确认后 record_vulnerability（类型：小程序任意跳转/小程序逻辑缺陷）。
