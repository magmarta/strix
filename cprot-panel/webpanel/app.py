#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Strix Pentest Kontrol Paneli — Flask web arayuzu (C-Prot Siber Güvenlik)."""
import json, os, re, secrets, subprocess, time, glob, functools
from flask import (Flask, request, session, redirect, url_for, jsonify,
                   render_template, send_file, abort, Response)

BASE = "/root/pentests/_web"
LIB  = "/opt/pentest/webpanel"
CONF = "/etc/pentest/panel.json"
os.makedirs(BASE, exist_ok=True)

def load_conf():
    d = {"user": "admin", "pass": "admin", "secret": secrets.token_hex(16)}
    if os.path.exists(CONF):
        try: d.update(json.load(open(CONF)))
        except Exception: pass
    else:
        json.dump(d, open(CONF, "w"), indent=2); os.chmod(CONF, 0o600)
    return d
CONF_D = load_conf()

app = Flask(__name__, template_folder=os.path.join(LIB, "templates"))
app.secret_key = CONF_D["secret"]
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.jinja_env.auto_reload = True

# ---- Strix kabiliyet katalogu (wizard'da gosterilir) ----
CAPS = [
  {"key":"ip","ad":"Ağ & Host Keşfi","ikon":"🌐","grup":"Keşif",
   "aciklama":"Canlı hostlar, işletim sistemi ve servis parmak izi tespiti."},
  {"key":"port","ad":"Port Taraması","ikon":"🔌","grup":"Keşif",
   "aciklama":"TCP/UDP açık portlar, çalışan servisler ve sürümleri (nmap benzeri)."},
  {"key":"dizin","ad":"Dizin & İçerik Keşfi","ikon":"📁","grup":"Keşif",
   "aciklama":"Gizli dizinler, yedek dosyalar, yönetim panelleri, hassas dosyalar."},
  {"key":"web","ad":"Web Uygulama Güvenliği","ikon":"🕸️","grup":"Uygulama",
   "aciklama":"OWASP Top 10: SQLi, XSS, IDOR, SSRF, CSRF, komut enjeksiyonu, dosya yükleme, XXE, SSTI."},
  {"key":"api","ad":"API Güvenliği","ikon":"🔗","grup":"Uygulama",
   "aciklama":"REST/GraphQL: BOLA/BFLA, aşırı veri ifşası, kütle atama, hız sınırı."},
  {"key":"kimlik","ad":"Kimlik Doğrulama & Yetki","ikon":"🔑","grup":"Uygulama",
   "aciklama":"Varsayılan/zayıf parola, oturum, JWT, yatay/dikey yetki yükseltme."},
  {"key":"zafiyet","ad":"Zafiyet & CVE Taraması","ikon":"🐛","grup":"Zafiyet",
   "aciklama":"Keşfedilen servis/sürümlerdeki bilinen zafiyetleri ve CVE'leri tespit/doğrula."},
  {"key":"ssl","ad":"SSL/TLS Güvenliği","ikon":"🔒","grup":"Zafiyet",
   "aciklama":"Zayıf şifreleme paketleri, eski protokoller (SSLv3/TLS1.0), sertifika hataları."},
  {"key":"arp","ad":"ARP Spoofing / MITM","ikon":"🎭","grup":"Ağ (L2)",
   "aciklama":"Yerel segmentte ARP zehirleme ile ortadaki adam senaryosu. (L2 erişimi gerekir.)"},
  {"key":"zehirleme","ad":"Poisoning (DNS/LLMNR)","ikon":"☠️","grup":"Ağ (L2)",
   "aciklama":"ARP/DNS/LLMNR/NBT-NS zehirleme (Responder tarzı) ile kimlik yakalama."},
  {"key":"dos","ad":"Dayanıklılık Gözlemi","ikon":"📉","grup":"Ağ (L2)",
   "aciklama":"Yalnızca gözlemsel; yıkıcı DoS YAPILMAZ."},
]
GRUPLAR = ["Keşif","Uygulama","Zafiyet","Ağ (L2)"]

# ---- yardimcilar ----
def login_required(f):
    @functools.wraps(f)
    def w(*a, **k):
        if not session.get("u"): 
            if request.path.startswith("/api/"): return jsonify(error="oturum yok"), 401
            return redirect(url_for("login"))
        return f(*a, **k)
    return w

def read_status(rundir):
    p = os.path.join(rundir, "status.json")
    try: return json.load(open(p))
    except Exception: return {}

def run_meta(rid):
    rd = os.path.join(BASE, rid)
    st = read_status(rd)
    prm = {}
    try: prm = json.load(open(os.path.join(rd, "params.json")))
    except Exception: pass
    return {"id":rid, "status":st.get("status","?"), "started":st.get("started"),
            "ended":st.get("ended"), "pdf":st.get("pdf"), "app":prm.get("app"),
            "firma":prm.get("firma"), "hedef":prm.get("ip") or prm.get("url"),
            "turler":prm.get("turler",[]), "mod":prm.get("mod")}

# ---- rotalar ----
@app.route("/login", methods=["GET","POST"])
def login():
    err = ""
    if request.method == "POST":
        if request.form.get("u")==CONF_D["user"] and request.form.get("p")==CONF_D["pass"]:
            session["u"] = request.form["u"]; return redirect(url_for("index"))
        err = "Kullanıcı adı veya şifre hatalı."
    return render_template("login.html", err=err)

@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))

@app.route("/")
@login_required
def index():
    return render_template("index.html", caps=CAPS, gruplar=GRUPLAR, user=session["u"])

@app.route("/api/start", methods=["POST"])
@login_required
def api_start():
    d = request.get_json(force=True)
    turler = [t for t in d.get("turler",[]) if t]
    if not turler: return jsonify(error="En az bir saldırı türü seçin"), 400
    if not (d.get("ip") or d.get("url")): return jsonify(error="Hedef (ip veya url) gerekli"), 400
    rid = time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)
    rd = os.path.join(BASE, rid); os.makedirs(rd, exist_ok=True)
    params = {"ip":d.get("ip","").strip(), "url":d.get("url","").strip(),
              "app":d.get("app","").strip(), "firma":d.get("firma","").strip(),
              "turler":turler, "mod":d.get("mod","standard"),
              "butce":d.get("butce","").strip(), "talimat":d.get("talimat","").strip(),
              "kullanici":d.get("kullanici","").strip(), "parola":d.get("parola","").strip(),
              "kimlikler":[str(x).strip() for x in (d.get("kimlikler") or []) if str(x).strip()]}
    json.dump(params, open(os.path.join(rd,"params.json"),"w"), ensure_ascii=False, indent=2)
    json.dump({"status":"starting"}, open(os.path.join(rd,"status.json"),"w"))
    # arka planda, SSH/panelden bagimsiz calissin
    subprocess.Popen(["/usr/bin/setsid","/usr/bin/python3",os.path.join(LIB,"runner.py"),rd],
                     stdout=open(os.path.join(rd,"runner.out"),"w"),
                     stderr=subprocess.STDOUT, start_new_session=True)
    return jsonify(id=rid)

@app.route("/api/status/<rid>")
@login_required
def api_status(rid):
    rd = os.path.join(BASE, rid)
    if not os.path.isdir(rd): abort(404)
    st = read_status(rd)
    logp = os.path.join(rd,"console.log")
    log = ""
    if os.path.exists(logp):
        try: log = open(logp,encoding="utf-8",errors="replace").read()[-16000:]
        except Exception: log = ""
    return jsonify(status=st.get("status","?"), ended=st.get("ended"),
                   pdf=st.get("pdf"), error=st.get("error"), log=log)

@app.route("/api/runs")
@login_required
def api_runs():
    runs = []
    for rid in sorted(os.listdir(BASE), reverse=True):
        if os.path.isdir(os.path.join(BASE,rid)): runs.append(run_meta(rid))
    return jsonify(runs=runs)

@app.route("/api/report/<rid>")
@login_required
def api_report(rid):
    rd = os.path.join(BASE, rid)
    st = read_status(rd)
    pdf = os.path.join(rd, st.get("pdf") or "rapor.pdf")
    if not os.path.exists(pdf): abort(404)
    m = run_meta(rid)
    fn = f"Rapor_{(m['firma'] or 'rapor')}_{(m['app'] or rid)}.pdf".replace(" ","_")
    return send_file(pdf, as_attachment=True, download_name=fn)

@app.route("/api/stop/<rid>", methods=["POST"])
@login_required
def api_stop(rid):
    rd = os.path.join(BASE, rid); st = read_status(rd)
    for k in ("child_pid","pid"):
        if st.get(k):
            try: os.killpg(os.getpgid(st[k]), 15)
            except Exception:
                try: os.kill(st[k], 15)
                except Exception: pass
    json.dump({**st,"status":"stopped","ended":int(time.time())},
              open(os.path.join(rd,"status.json"),"w"))
    return jsonify(ok=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PANEL_PORT","80")), threaded=True)
