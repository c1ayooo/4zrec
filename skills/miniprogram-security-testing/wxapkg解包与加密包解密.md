# wxapkg 解包与 V1MMWX 加密包解密

wxapkg 是微信小程序的二进制包格式。平台 `miniprogram_analyze` 已内置解析与解密（含 PC 微信 4.x 加密包），本条目是格式规范与手工兜底方法。

## 包的来源与获取

- PC 微信 4.x（radium 新架构）缓存目录：`<用户目录>/AppData/Roaming/Tencent/xwechat/radium/users/<账号>/applet/packages/<appid>/<版本>/__APP__.wxapkg`，分包为同目录 `_subpackages_*.wxapkg`。WSL 下经 `/mnt/<盘>/Users/...` 直读，无需 root。
- PC 微信 3.x 旧架构：`<用户目录>/Documents/WeChat Files/Applet/<appid>/<hash>/*.wxapkg`。
- Android（root）：`/data/data/com.tencent.mm/MicroMsg/<用户哈希>/appbrand/pkg/` 下的 `_-<版本>.wxapkg`。
- **AppID 就是包所在目录名**（如 wx67f00cf6ceff6dcf），是解密加密包的必要入参。

## wxapkg 二进制格式

```
偏移 0      1B    起始标记 0xBE
偏移 1-4    4B    info1（大端，恒 0）
偏移 5-8    4B    索引区长度（大端，含文件数字段）
偏移 9-12   4B    数据区长度（大端）
偏移 13     1B    结束标记 0xED
偏移 14-17  4B    文件数量（大端）
偏移 18+    文件条目区，每条:
             4B 文件名长度（大端） + N B 文件名(UTF-8) + 4B 数据偏移 + 4B 数据大小
条目区之后  文件数据区（偏移为相对文件起始的绝对偏移）
```

- 包内路径常为 `/app.js` 绝对形式，还原时去掉前导斜杠；注意 `../` 路径穿越条目要跳过。
- 旧布局变体：文件数在偏移 9-12、条目从 14 开始，解析失败时两种布局都试。

## V1MMWX 加密包解密（PC 微信 4.x）

文件以 `V1MMWX` 6 字节魔数开头：

1. 前 1024 字节：AES-256-CBC 解密，key = PBKDF2-HMAC-SHA1(appid, "saltiest", 1000 次, 32 字节)，IV = 字面量 `"the iv: 16 bytes"`。
2. 第 1024 字节起：逐字节 XOR appid 的倒数第 2 个字符（appid 少于 2 字符时用 0x66）。
3. 明文 = 解密后的前 1023 字节（第 1024 字节为占位，丢弃）‖ XOR 解出的尾部。

解密后首字节应为 0xBE（wxapkg 起始标记），可作正确性校验。AppID 错误时 AES 段解出乱码、校验必败。

## 分包与还原边界

- 主包 + `_subpackages_*` 分包需合并到同一目录；**同名路径后包覆盖先包**——覆盖清单是审计线索（后传的分包可能覆盖主包逻辑）。
- app.json 是攻击面地图：pages 路由、subpackages 分包、plugins（`plugin://` 声明）、permission 声明、requiredBackgroundModes。
- 常规解包不覆盖：插件包（plugin 独立包）、Worker 脚本（`workers/` 配置目录）、WASM（wxwebassembly）、开放数据域子包——这些位置常藏校验与业务逻辑，发现缺文件时用 unveilr/wxappUnpacker 手工兜底。
- 解包产物为压缩 JS，用 node + prettier/js-beautify 格式化后再审计可读性更好。
