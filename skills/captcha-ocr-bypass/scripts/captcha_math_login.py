#!/usr/bin/env python3
"""math 验证码自动解析登录（RuoYi 系通用）

用法: python3 captcha_math_login.py <base_url> <api_prefix> <username> <password>
例:   python3 captcha_math_login.py https://example.com partner-back 13800000000 your-password

关键点（RuoYi 系 math 验证码实测）：
  1. RuoYi captchaImage 返回 JSON，`img` 是 base64（不是图片流），带 `uuid`
  2. 验证码图真实格式是 `a op b =?`（160x60 JPEG，蓝字白底）
  3. **OCR 前必须裁掉右侧 38%**（只留左侧 62% 宽度）——ddddocr 会把
     `=?` 识别成多余字符（`9*7=?` → `9t7a`），裁后变干净的 `9*7`
  4. 裁剪后数字很稳，运算符会丢或变 `t` —— 运算符不确定时依次枚举 `+ - *`
     验证码错误返回「验证码已失效」且不计登录失败次数，枚举零成本
  5. 账号密码错返回「用户不存在/密码错误」，与验证码错消息不同，可直接区分
"""
import requests, urllib3, subprocess, time, base64, re, io, sys, os

urllib3.disable_warnings()

CROP = 0.62          # 只保留左侧 62% 宽度，去掉 `=?`
OPS = ['+', '-', '*']
OP_MAP = {'x': '*', 'X': '*', '×': '*', 'y': '*', 'Y': '*', 't': '+', 'T': '+'}


def _get_ocr():
    """ddddocr 实例（全局单例，避免重复加载模型）"""
    global _OCR
    try:
        return _OCR
    except NameError:
        import ddddocr
        _OCR = ddddocr.DdddOcr(show_ad=False)
        return _OCR


def read_expr(sess, api_base, retries=5):
    """取一张验证码，裁剪 + OCR，返回 {a, b, op, raw, uuid} 或 None
    op 为 None 表示运算符没看准——调用方应枚举 OPS
    """
    from PIL import Image
    for _ in range(retries):
        r = sess.get(f'{api_base}/captchaImage?t={int(time.time()*1000)}', timeout=15)
        if len(r.content) < 300:
            time.sleep(2); continue
        ct = r.headers.get('Content-Type', '')
        if 'json' in ct:
            d = r.json()
            if not d.get('captchaEnabled', True):
                return {'a': None, 'b': None, 'op': '__disabled__', 'raw': '', 'uuid': ''}
            img = Image.open(io.BytesIO(base64.b64decode(d.get('img', ''))))
            uuid = d.get('uuid', '')
        else:
            img = Image.open(io.BytesIO(r.content))
            uuid = ''
        w, h = img.size
        buf = io.BytesIO()
        img.crop((0, 0, int(w * CROP), h)).save(buf, format='JPEG', quality=95)
        txt = _get_ocr().classification(buf.getvalue()).strip()
        clean = re.sub(r'[^0-9+\-*xXtTyY×]', '', txt)
        digits = re.findall(r'\d', clean)
        if len(digits) < 2:
            continue
        a, b = int(digits[0]), int(digits[1])
        m = re.search(r'\d([+\-*/xXtTyY×])\d', clean)
        op = None
        if m:
            op = OP_MAP.get(m.group(1), m.group(1))
            if op not in OPS:
                op = None
        return {'a': a, 'b': b, 'op': op, 'raw': txt, 'uuid': uuid}
    return None


def answer(op, a, b):
    if op == '+': return a + b
    if op == '-': return a - b
    if op == '*': return a * b
    return None


def login(base, prefix, user, pwd, retries=25, verbose=True):
    S = requests.Session()
    S.verify = False
    S.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120'})
    api_base = base if prefix == '' else f'{base}/{prefix}'
    for i in range(retries):
        got = read_expr(S, api_base)
        if got is None:
            if verbose: print('验证码空图（限流/服务异常）')
            return None
        if got['op'] == '__disabled__':
            if verbose: print('captchaEnabled=false，不带验证码重试')
            got = {'a': 0, 'b': 0, 'op': '+', 'uuid': ''}
        ops = [got['op']] if got['op'] in OPS else OPS
        for op in ops:
            ans = answer(op, got['a'], got['b'])
            if ans is None:
                continue
            r = S.post(f'{api_base}/login', json={
                'username': user, 'password': pwd,
                'code': str(ans), 'uuid': got['uuid'],
            }, timeout=15)
            try:
                d = r.json()
            except Exception:
                if verbose: print('非 JSON 响应:', r.text[:120])
                return None
            if d.get('code') == 200 and d.get('token'):
                return d['token']
            msg = str(d.get('msg', ''))
            if '验证码' in msg:
                if verbose: print(f'  [{i+1}] 验证码未中（OCR={got["raw"]!r} op={op} ans={ans}），重试')
                continue          # 验证码错 → 换运算符 / 重取图，不计失败次数
            if verbose: print(f'登录失败: {d.get("code")} {msg}')
            return None
    if verbose: print('验证码重试耗尽')
    return None


if __name__ == '__main__':
    if len(sys.argv) < 5:
        print(__doc__)
        sys.exit(1)
    base, prefix, u, p = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    tok = login(base, prefix, u, p)
    if tok:
        print(f'SUCCESS token={tok[:50]}...')
        open('/tmp/login_token.txt', 'w').write(tok)
    else:
        print('FAIL')
