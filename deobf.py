from __future__ import annotations

import ast
import builtins
import io
import keyword
import operator
import re
import tokenize
import zlib
from pathlib import Path

g = {"ok": False, "n": 0}

p1 = re.compile(
    r"(?is)(?:b|br|rb)(?:" + '"""' + r"(?:.|\n)*?" + '"""'
    + r"|'''(?:.|\n)*?'''|'(?:\\.|[^'])*'|\"(?:\\.|[^\"])*\")"
)
p2 = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{11,}$")
p3 = re.compile(r"^[IiLlO0oDMS2NmnXWxwJj_]+$")
p4 = re.compile(r"((?:b|br|rb|r|u|f)?(?:'[^'\\]*(?:\\.[^'\\]*)*'|\"[^\"\\]*(?:\\.[^\"\\]*)*\"))\s*\[\s*::\s*\+\-\+\-\(\-\(\+1\)\)\s*\]", re.I)
p5 = re.compile(r"\b\w+\s*\(\s*(b(?:'[^'\\]*(?:\\.[^'\\]*)*'|\"[^\"\\]*(?:\\.[^\"\\]*)*\"))\s*\)\s*\.decode\(\s*('utf8'|\"utf8\"|'utf-8'|\"utf-8\")\s*\)")
p6 = re.compile(r"\b\w+\s*\(\s*('[^'\\]*(?:\\.[^'\\]*)*'|\"[^\"\\]*(?:\\.[^\"\\]*)*\")\s*\)")
p7 = re.compile(r"^\s*\w+\(\)\[(.+?)\]\s*=\s*(.+?)\s*$")
p8 = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
bl = set(dir(builtins))


def logo():
    t = "\033[31m"
    e = "\033[0m"
    b = """
             %                                                    %
              %%                                                %%
               %%%                                            %%%
                 %%%%                                      %%%%
                   %%%%%                                %%%%%
                     %%%%%%%                        %%%%%%%
                       %%%%%%%%:                :%%%%%%%%
                         %%%%%%%%%%          %%%%%%%%%%
                           :%%%%%%%%        %%%%%%%%:
                              %%%%%%        %%%%%%
                               %%%%.         %%%%
                               %%%%          %%%%
                              :%%%%%        %%%%%:
                              %%%%%%%%%  %%%%%%%%%
                                %%%%%%%%%%%%%%%%
                                  %%%%%%%%%%%%
                                    #%%%%%%#
                                       %%

                        Деобфускатор создавал ProcHacker."""
    print(t + b + e)


class Err(ValueError):
    pass


def gb(src):
    res = []
    for x in p1.finditer(src):
        try:
            v = ast.literal_eval(x.group(0))
        except Exception:
            continue
        if type(v) == bytes or isinstance(v, bytes):
            res.append(v)
    return res


def dec(v):
    try:
        return zlib.decompress(v).decode("utf-8")
    except Exception:
        return None


def unp(vals):
    for v in vals:
        d = dec(v)
        if d is not None:
            return d

    d = dec(b"".join(vals))
    if d is not None:
        return d

    i = 0
    while i < len(vals):
        c = b""
        j = i
        while j < len(vals):
            c = c + vals[j]
            d = dec(c)
            if d is not None:
                return d
            j = j + 1
        i = i + 1

    raise Err("Could not find a valid Hyperion zlib payload.")


def chk(v):
    if v in bl:
        return False
    if keyword.iskeyword(v):
        return False
    if v[:2] == "__" and v[-2:] == "__":
        return False
    if not p2.fullmatch(v):
        return False
    if not p3.fullmatch(v):
        return False
    return True


def scan(src):
    cl = set()
    fn = set()
    vr = set()
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return cl, fn, vr
    for n in ast.walk(tree):
        if isinstance(n, ast.ClassDef):
            if chk(n.name):
                cl.add(n.name)
        elif isinstance(n, ast.FunctionDef) or isinstance(n, ast.AsyncFunctionDef):
            if chk(n.name):
                fn.add(n.name)
        elif isinstance(n, ast.Name):
            if isinstance(n.ctx, ast.Store) or isinstance(n.ctx, ast.Param if hasattr(ast, "Param") else ast.Store):
                if chk(n.id):
                    vr.add(n.id)
        elif isinstance(n, ast.arg):
            if chk(n.arg):
                vr.add(n.arg)
    return cl, fn, vr


def toks(src):
    res = set()
    s = io.StringIO(src).readline
    try:
        for t in tokenize.generate_tokens(s):
            if t.type == tokenize.NAME:
                if chk(t.string):
                    res.add(t.string)
    except tokenize.TokenError:
        pass
    return res


def mk(src):
    cl, fn, vr = scan(src)
    tk = toks(src)
    mp = {}
    idx = 1
    for n in sorted(cl):
        mp[n] = "C" + str(idx)
        idx += 1
    idx = 1
    for n in sorted(fn - set(mp)):
        mp[n] = "f" + str(idx)
        idx += 1
    rest = sorted((tk | vr) - set(mp))
    idx = 1
    for n in rest:
        mp[n] = "v" + str(idx)
        idx = idx + 1
    return mp


def fxs(v, mp):
    try:
        d = ast.literal_eval(v)
    except Exception:
        return v
    if isinstance(d, str) and d in mp:
        pr = ""
        tmp = v
        while tmp and tmp[0] in "rRuUbBfF":
            pr = pr + tmp[0]
            tmp = tmp[1:]
        q = "'"
        if tmp[:3] == '"""':
            q = '"""'
        elif tmp[:3] == "'''":
            q = "'''"
        elif tmp[:1] == '"':
            q = '"'
        return pr + q + mp[d] + q
    return v


def ren(src):
    mp = mk(src)
    if len(mp) == 0:
        return src
    out = []
    s = io.StringIO(src).readline
    try:
        for t in tokenize.generate_tokens(s):
            v = t.string
            if t.type == tokenize.NAME and v in mp:
                v = mp[v]
            elif t.type == tokenize.STRING:
                v = fxs(v, mp)
            out.append(tokenize.TokenInfo(t.type, v, t.start, t.end, t.line))
        return tokenize.untokenize(out)
    except tokenize.TokenError:
        return src


def rp(v):
    return repr(v)


def ev(n):
    bo = {
        ast.Add: operator.add, ast.Sub: operator.sub,
        ast.Mult: operator.mul, ast.Div: operator.truediv,
        ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod,
        ast.Pow: operator.pow,
    }
    uo = {
        ast.UAdd: operator.pos, ast.USub: operator.neg,
        ast.Invert: operator.invert, ast.Not: operator.not_,
    }
    if isinstance(n, ast.Expression):
        return ev(n.body)
    if isinstance(n, ast.Constant):
        return n.value
    if isinstance(n, ast.UnaryOp):
        if type(n.op) in uo:
            return uo[type(n.op)](ev(n.operand))
    if isinstance(n, ast.BinOp):
        if type(n.op) in bo:
            return bo[type(n.op)](ev(n.left), ev(n.right))
    if isinstance(n, ast.BoolOp):
        vv = [ev(x) for x in n.values]
        if isinstance(n.op, ast.And):
            r = vv[0]
            for x in vv:
                r = x
                if not r:
                    break
            return r
        if isinstance(n.op, ast.Or):
            r = vv[0]
            for x in vv:
                r = x
                if r:
                    break
            return r
    if isinstance(n, ast.Compare):
        if len(n.ops) == 1 and len(n.comparators) == 1:
            l = ev(n.left)
            r = ev(n.comparators[0])
            o = n.ops[0]
            if isinstance(o, ast.Eq): return l == r
            if isinstance(o, ast.NotEq): return l != r
            if isinstance(o, ast.Lt): return l < r
            if isinstance(o, ast.LtE): return l <= r
            if isinstance(o, ast.Gt): return l > r
            if isinstance(o, ast.GtE): return l >= r
    raise ValueError


def evx(e):
    return ev(ast.parse(e, mode="eval"))


def rev(m):
    try:
        v = ast.literal_eval(m.group(1))
    except Exception:
        return m.group(0)
    if type(v) in [str, bytes]:
        return rp(v[::-1])
    return m.group(0)


def uhx(m):
    try:
        v = ast.literal_eval(m.group(1))
    except Exception:
        return m.group(0)
    if not isinstance(v, bytes):
        return m.group(0)
    try:
        return rp(bytes.fromhex(v.decode("ascii")).decode("utf-8"))
    except Exception:
        return m.group(0)


def evc(m):
    try:
        v = ast.literal_eval(m.group(1))
    except Exception:
        return m.group(0)
    if not isinstance(v, str):
        return m.group(0)
    if not re.fullmatch(r"[0-9+\-*/%(). _'\",A-Za-z]+", v):
        return m.group(0)
    try:
        return rp(evx(v))
    except Exception:
        return m.group(0)


def simp(src):
    prev = None
    cur = src
    n = 0
    while n < 12:
        if cur == prev:
            break
        prev = cur
        cur = p4.sub(rev, cur)
        cur = p5.sub(uhx, cur)
        cur = p6.sub(evc, cur)
        n += 1
    return cur


def cval(e):
    e = simp(e.strip())
    if e[:7] == "lambda ":
        return None
    if e in ("True", "False", "None"):
        return ast.literal_eval(e)
    try:
        return ast.literal_eval(e)
    except Exception:
        pass
    try:
        return evx(e)
    except Exception:
        return None


def bcon(src):
    cs = {}
    ci = 0
    lines = src.splitlines()
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        s = line.strip()
        if (s.startswith("import ") or s.startswith("from ")) and idx > 5:
            ci = idx
            break
        m = p7.match(line)
        if m:
            k = cval(m.group(1))
            if isinstance(k, str) and p8.fullmatch(k):
                val = cval(m.group(2))
                if isinstance(val, (str, int, float, bool)) or val is None:
                    cs[k] = val
        idx += 1
    return cs, ci


def rplc(src, cs):
    out = []
    s = io.StringIO(src).readline
    try:
        for t in tokenize.generate_tokens(s):
            v = t.string
            if t.type == tokenize.NAME and v in cs:
                v = rp(cs[v])
            out.append(tokenize.TokenInfo(t.type, v, t.start, t.end, t.line))
        return tokenize.untokenize(out)
    except tokenize.TokenError:
        return src


def clean(src):
    src = simp(src)
    cs, ci = bcon(src)
    if not cs or ci == 0:
        return src
    u = "\n".join(src.splitlines()[ci:])
    u = rplc(u, cs)
    u = simp(u)
    return u


def fmt(src):
    lines = src.splitlines()
    tmp = []
    for l in lines:
        if l.strip() == "exec('')":
            continue
        tmp.append(l)
    src = "\n".join(tmp)
    try:
        return ast.unparse(ast.parse(src)) + "\n"
    except SyntaxError:
        return src


def deobf(src, norm=True):
    vals = gb(src)
    if len(vals) == 0:
        raise Err("Could not find bytes payload.")
    d = unp(vals)
    if norm:
        d = simp(d)
        d = ren(d)
        d = simp(d)
        d = ren(d)
        d = clean(d)
        d = fmt(d)
    g["ok"] = True
    g["n"] = g["n"] + 1
    return d


def proc(p, o=None, norm=True):
    p = Path(p)
    if o is None:
        o = p.with_name(p.stem + "_deobf.py")
    o = Path(o)
    src = p.read_text(encoding="utf-8", errors="ignore")
    d = deobf(src, norm)
    o.write_text(d, encoding="utf-8")
    return o


def main():
    logo()
    p = ""
    while p == "" or len(p) < 1:
        p = input("Введите путь к файлу: ").strip().strip('"')
    r = proc(p)
    print("Deobfuscated file written to: " + str(r))


if __name__ == "__main__":
    main()
