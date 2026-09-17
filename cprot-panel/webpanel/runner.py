#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Web panel arka plan calistiricisi: params.json -> saldir -> status.json + rapor.pdf"""
import json, os, re, subprocess, sys, time, shutil, glob

ANSI = re.compile(r'\x1b\[[0-9;]*m')

# Olumcul LLM/API hatalari -> Turkce aciklama
FATAL = [
    (re.compile(r'credit balance is too low', re.I),
     "Anthropic API kredi bakiyesi yetersiz. console.anthropic.com → Plans & Billing’den kredi yükleyin."),
    (re.compile(r'authentication_error|invalid x-api-key|invalid_api_key|could not resolve authentication', re.I),
     "Anthropic API anahtarı geçersiz veya yetkisiz."),
    (re.compile(r'rate_limit|overloaded', re.I),
     "Anthropic API geçici olarak yoğun/limit aşıldı. Bir süre sonra tekrar deneyin."),
    (re.compile(r'permission_error|not scoped to a workspace', re.I),
     "API anahtarı workspace’e bağlı değil veya yetkisiz."),
]

def wstatus(rundir, **kw):
    p = os.path.join(rundir, "status.json")
    cur = {}
    if os.path.exists(p):
        try: cur = json.load(open(p))
        except Exception: cur = {}
    cur.update(kw)
    tmp = p + ".tmp"; json.dump(cur, open(tmp, "w"), ensure_ascii=False, indent=2); os.replace(tmp, p)

def main(rundir):
    params = json.load(open(os.path.join(rundir, "params.json")))
    cmd = ["/usr/local/bin/saldir", "--saldiriturleri", ",".join(params["turler"])]
    if params.get("ip"):   cmd += ["--ip", params["ip"]]
    if params.get("url"):  cmd += ["--url", params["url"]]
    cmd += ["--app", params.get("app") or "hedef", "--firma", params.get("firma") or "Belirtilmedi",
            "--mod", params.get("mod") or "standard"]
    if params.get("butce"):   cmd += ["--butce", str(params["butce"])]
    if params.get("talimat"): cmd += ["--talimat", params["talimat"]]
    if params.get("kullanici"): cmd += ["--kullanici", params["kullanici"]]
    if params.get("parola"): cmd += ["--parola", params["parola"]]
    for _k in (params.get("kimlikler") or []):
        if _k: cmd += ["--kimlik", _k]
    if params.get("kullaniciadi"): cmd += ["--kullaniciadi", params["kullaniciadi"]]

    logp = os.path.join(rundir, "console.log")
    wstatus(rundir, status="running", pid=os.getpid(), started=int(time.time()), cmd=" ".join(cmd))
    rc = 1
    with open(logp, "w", buffering=1) as log:
        log.write("$ " + " ".join(cmd) + "\n\n")
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            wstatus(rundir, child_pid=proc.pid)
            for line in proc.stdout: log.write(line)
            rc = proc.wait()
        except Exception as e:
            log.write(f"\n[RUNNER HATA] {e}\n")
            wstatus(rundir, status="failed", error=str(e), ended=int(time.time()), rc=rc); return

    txt = ANSI.sub("", open(logp, encoding="utf-8", errors="replace").read())

    # 1) Olumcul hata var mi?
    for rx, msg in FATAL:
        if rx.search(txt):
            wstatus(rundir, status="failed", error=msg, ended=int(time.time()), rc=rc); return

    # 2) PDF yolunu bul
    pdf = ""
    m = re.search(r'Rapor haz[ıi]r:\s*(\S+\.pdf)', txt)
    if m and os.path.exists(m.group(1)):
        pdf = m.group(1)
    else:
        mr = re.search(r'Çıktı\s*:\s*(\S+)', txt)
        if mr:
            cand = sorted(glob.glob(os.path.join(mr.group(1), "*.pdf")), key=os.path.getmtime)
            if cand: pdf = cand[-1]

    if pdf and os.path.exists(pdf):
        dest = os.path.join(rundir, "rapor.pdf")
        try: shutil.copy(pdf, dest)
        except Exception: pass
        wstatus(rundir, status="done" if rc == 0 else "done_warn",
                ended=int(time.time()), rc=rc, pdf="rapor.pdf", pdf_source=pdf)
    else:
        wstatus(rundir, status="failed", ended=int(time.time()), rc=rc,
                error="Tarama tamamlandı ancak PDF üretilemedi. Konsol çıktısını inceleyin.")

if __name__ == "__main__":
    main(sys.argv[1])
