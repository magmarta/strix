#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Strix ciktisindan Turkce sizma testi raporu (PDF). Oncelik: Strix markdown raporu; yedek: SARIF/JSON."""
import argparse, json, os, re, sys, datetime, glob, html

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                TableStyle, PageBreak, HRFlowable, Preformatted)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase.pdfmetrics import registerFontFamily

def _find_font(name):
    for root in ("/usr/share/fonts", "/usr/local/share/fonts"):
        hits = glob.glob(os.path.join(root, "**", name), recursive=True)
        if hits: return hits[0]
    return None

FONT, FONT_B, FONT_M = "Helvetica", "Helvetica-Bold", "Courier"
try:
    reg, bold = _find_font("DejaVuSans.ttf"), _find_font("DejaVuSans-Bold.ttf")
    mono = _find_font("DejaVuSansMono.ttf")
    if reg and bold:
        pdfmetrics.registerFont(TTFont("DejaVu", reg)); pdfmetrics.registerFont(TTFont("DejaVu-Bold", bold))
        FONT, FONT_B = "DejaVu", "DejaVu-Bold"
        if mono: pdfmetrics.registerFont(TTFont("DejaVuMono", mono)); FONT_M = "DejaVuMono"
        registerFontFamily("DejaVu", normal="DejaVu", bold="DejaVu-Bold", italic="DejaVu", boldItalic="DejaVu-Bold")
except Exception:
    pass

NAVY = colors.HexColor("#1a2b3c")
SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
SEV_TR = {"critical":"KRİTİK","high":"YÜKSEK","medium":"ORTA","low":"DÜŞÜK","info":"BİLGİ"}
SEV_COLOR = {"critical":colors.HexColor("#7b1113"),"high":colors.HexColor("#c0392b"),
             "medium":colors.HexColor("#e67e22"),"low":colors.HexColor("#d4a017"),"info":colors.HexColor("#2980b9")}
SARIF_LEVEL = {"error":"high","warning":"medium","note":"low","none":"info"}

def cvss_to_sev(v):
    try: v=float(v)
    except Exception: return None,""
    return ("critical" if v>=9 else "high" if v>=7 else "medium" if v>=4 else "low" if v>0 else "info"), str(v)

def load_sarif(run_dir):
    findings=[]
    for sf in glob.glob(os.path.join(run_dir,"**","*.sarif"), recursive=True):
        try: d=json.load(open(sf,encoding="utf-8"))
        except Exception: continue
        for run in d.get("runs",[]):
            rules={r.get("id"):r for r in run.get("tool",{}).get("driver",{}).get("rules",[])}
            for res in run.get("results",[]):
                rid=res.get("ruleId",""); rule=rules.get(rid,{}) or {}
                title=rule.get("name") or (rule.get("shortDescription",{}) or {}).get("text") or rid or "Bulgu"
                props=res.get("properties",{}) or {}
                sev,cvss=cvss_to_sev(props.get("security-severity") or props.get("cvss") or "")
                if not sev: sev=SARIF_LEVEL.get(res.get("level","warning"),"medium")
                findings.append(dict(title=str(title), sev=sev, cvss=cvss))
    return findings

SEMGREP_SEV={"ERROR":"high","WARNING":"medium","INFO":"low"}
def load_semgrep(path):
    try: d=json.load(open(path,encoding="utf-8"))
    except Exception: return []
    out=[]
    for r in d.get("results",[]):
        extra=r.get("extra",{}) or {}; meta=extra.get("metadata",{}) or {}
        sev=SEMGREP_SEV.get(str(extra.get("severity","WARNING")).upper(),"medium")
        rid=r.get("check_id","") or ""
        title=rid.split(".")[-1].replace("-"," ") if rid else "Kod bulgusu"
        loc=f"{r.get('path','')}:{r.get('start',{}).get('line','')}"
        cwe=meta.get("cwe"); owasp=meta.get("owasp"); tag=""
        if cwe: tag+="CWE: "+(", ".join(cwe) if isinstance(cwe,list) else str(cwe))
        if owasp: tag+=("  " if tag else "")+"OWASP: "+(", ".join(owasp) if isinstance(owasp,list) else str(owasp))
        out.append(dict(title=title,sev=sev,loc=loc,desc=extra.get("message","") or "",tag=tag,rule=rid))
    out.sort(key=lambda f: SEV_ORDER.get(f["sev"],9)); return out

def find_report_md(run_dir):
    cands=[]
    for mf in glob.glob(os.path.join(run_dir,"**","*.md"), recursive=True):
        low=os.path.basename(mf).lower()
        if any(p in low for p in ("penetration_test_report","report","final","summary","pentest")):
            cands.append(mf)
    if not cands: return ""
    cands.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    try: return open(cands[0],encoding="utf-8",errors="replace").read()
    except Exception: return ""

def md_inline(t):
    t=html.escape(t)
    t=re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', t)
    t=re.sub(r'__(.+?)__', r'<b>\1</b>', t)
    t=re.sub(r'`([^`]+)`', r'<font face="%s">\1</font>' % FONT_M, t)
    t=re.sub(r'(?<!\*)\*(?!\s)([^*\n]+?)(?<!\s)\*(?!\*)', r'<i>\1</i>', t)
    t=re.sub(r'\[([^\]]+)\]\((https?://[^)]+)\)', r'\1 (\2)', t)
    return t

def _md_table(rows, S):
    data=[[Paragraph(md_inline(c), S["td"]) for c in r] for r in rows]
    ncol=max(len(r) for r in data)
    for r in data:
        while len(r)<ncol: r.append(Paragraph("", S["td"]))
    w=176.0/ncol
    t=Table(data, colWidths=[w*mm]*ncol, repeatRows=1)
    t.setStyle(TableStyle([("GRID",(0,0),(-1,-1),0.4,colors.HexColor("#c9d2e0")),
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#e2e7f0")),
        ("FONTSIZE",(0,0),(-1,-1),8),("VALIGN",(0,0),(-1,-1),"TOP"),
        ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,0),(-1,-1),3),("LEFTPADDING",(0,0),(-1,-1),4)]))
    return t

def md_to_flowables(md, S):
    fl=[]; lines=md.split("\n"); i=0; n=len(lines); buf=[]
    def flush():
        if buf:
            txt=" ".join(x.strip() for x in buf).strip()
            if txt: fl.append(Paragraph(md_inline(txt), S["body"]))
            buf.clear()
    while i<n:
        ln=lines[i]; st=ln.strip()
        if st.startswith("```"):
            flush(); i+=1; code=[]
            while i<n and not lines[i].strip().startswith("```"): code.append(lines[i]); i+=1
            i+=1
            if code: fl.append(Preformatted("\n".join(code)[:8000], S["code"]))
            fl.append(Spacer(1,2*mm)); continue
        if "|" in st and i+1<n and "-" in lines[i+1] and set(lines[i+1].strip())<=set("|-: "):
            flush(); rows=[[c.strip() for c in st.strip().strip("|").split("|")]]; i+=2
            while i<n and "|" in lines[i] and lines[i].strip():
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")]); i+=1
            fl.append(_md_table(rows,S)); fl.append(Spacer(1,3*mm)); continue
        m=re.match(r'^(#{1,6})\s+(.*)$', st)
        if m:
            flush(); lvl=len(m.group(1))
            fl.append(Paragraph(md_inline(m.group(2)), {1:S["h1"],2:S["h2"],3:S["h3"]}.get(lvl,S["h4"]))); i+=1; continue
        if st in ("---","***","___"):
            flush(); fl.append(HRFlowable(width="100%",color=colors.HexColor("#ccd3df"))); i+=1; continue
        mb=re.match(r'^[-*+]\s+(.*)$', st)
        if mb: flush(); fl.append(Paragraph("•&nbsp; "+md_inline(mb.group(1)), S["bullet"])); i+=1; continue
        mn=re.match(r'^(\d+)\.\s+(.*)$', st)
        if mn: flush(); fl.append(Paragraph(mn.group(1)+".&nbsp; "+md_inline(mn.group(2)), S["bullet"])); i+=1; continue
        if st=="": flush(); i+=1; continue
        buf.append(ln); i+=1
    flush(); return fl

def P(text, style):
    return Paragraph(html.escape(str(text or "")).replace("\n","<br/>"), style)

def build(args):
    run_dir=args.run_dir
    findings=load_sarif(run_dir) if run_dir and os.path.isdir(run_dir) else []
    report_md=find_report_md(run_dir) if run_dir and os.path.isdir(run_dir) else ""
    findings.sort(key=lambda f: SEV_ORDER.get(f["sev"],9))
    ss=getSampleStyleSheet()
    S={
      "h1":ParagraphStyle("h1",parent=ss["Heading1"],fontName=FONT_B,fontSize=16,spaceBefore=8,spaceAfter=5,textColor=NAVY),
      "h2":ParagraphStyle("h2",parent=ss["Heading2"],fontName=FONT_B,fontSize=13,spaceBefore=8,spaceAfter=4,textColor=NAVY),
      "h3":ParagraphStyle("h3",parent=ss["Heading3"],fontName=FONT_B,fontSize=11.5,spaceBefore=6,spaceAfter=3,textColor=colors.HexColor("#2c3e50")),
      "h4":ParagraphStyle("h4",parent=ss["Heading4"],fontName=FONT_B,fontSize=10.5,spaceBefore=5,spaceAfter=2,textColor=colors.HexColor("#2c3e50")),
      "body":ParagraphStyle("body",parent=ss["BodyText"],fontName=FONT,fontSize=9.5,leading=13,spaceAfter=3),
      "bullet":ParagraphStyle("bullet",parent=ss["BodyText"],fontName=FONT,fontSize=9.5,leading=13,leftIndent=10,spaceAfter=2),
      "td":ParagraphStyle("td",parent=ss["BodyText"],fontName=FONT,fontSize=8,leading=10),
      "code":ParagraphStyle("code",parent=ss["Code"],fontName=FONT_M,fontSize=7.5,leading=9.5,backColor=colors.HexColor("#f2f4f7")),
      "small":ParagraphStyle("small",parent=ss["BodyText"],fontName=FONT,fontSize=8,textColor=colors.grey),
    }
    center=ParagraphStyle("center",parent=ss["Title"],fontName=FONT_B,alignment=TA_CENTER,fontSize=26,textColor=NAVY)
    sub=ParagraphStyle("sub",parent=ss["Normal"],fontName=FONT,alignment=TA_CENTER,fontSize=12,textColor=colors.grey)

    doc=SimpleDocTemplate(args.out,pagesize=A4,topMargin=20*mm,bottomMargin=18*mm,leftMargin=18*mm,rightMargin=18*mm,
                          title=f"Sızma Testi Raporu - {args.uygulama or args.hedef}", author="C-Prot Siber Güvenlik")
    E=[]; tarih=datetime.datetime.now().strftime("%d.%m.%Y %H:%M")
    # KAPAK
    E+=[Spacer(1,45*mm),Paragraph("SIZMA TESTİ RAPORU",center),Spacer(1,4*mm),
        Paragraph("Penetration Test Report",sub),Spacer(1,20*mm)]
    kapak=[["Firma / Müşteri",args.firma or "-"],["Test Edilen Uygulama",args.uygulama or "-"],
           ["Hedef",args.hedef or "-"],["Saldırı Türleri",(args.turler or "-").replace(","," , ")],
           ["Rapor Tarihi",tarih],["Test Aracı","Strix AI Pentest Agent"]]
    tw=ParagraphStyle("tw",parent=S["body"],textColor=colors.white,fontName=FONT_B)
    t=Table([[P(a,tw),P(b,S["body"])] for a,b in kapak],colWidths=[55*mm,105*mm])
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(0,-1),NAVY),("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ("GRID",(0,0),(-1,-1),0.5,colors.HexColor("#d0d0d0")),
        ("ROWBACKGROUNDS",(1,0),(1,-1),[colors.white,colors.HexColor("#f2f4f7")]),
        ("LEFTPADDING",(0,0),(-1,-1),8),("TOPPADDING",(0,0),(-1,-1),7),("BOTTOMPADDING",(0,0),(-1,-1),7)]))
    E+=[t,Spacer(1,28*mm),
        Paragraph("GİZLİLİK UYARISI: Bu rapor yalnızca yetkili sızma testi kapsamında hazırlanmıştır ve gizli bilgi içerir. İzinsiz paylaşılamaz.",S["small"]),
        PageBreak()]

    # Onem ozeti (SARIF varsa)
    if findings:
        counts={}
        for f in findings: counts[f["sev"]]=counts.get(f["sev"],0)+1
        E+=[Paragraph("Bulgu Özeti",S["h1"]),HRFlowable(width="100%",color=NAVY),Spacer(1,3*mm)]
        rows=[[P("Önem Derecesi",tw),P("Adet",tw)]]
        stl=[("BACKGROUND",(0,0),(-1,0),NAVY),("GRID",(0,0),(-1,-1),0.5,colors.grey),
             ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5)]
        r=1
        for sev in ["critical","high","medium","low","info"]:
            if counts.get(sev):
                cs=ParagraphStyle("cs",parent=S["body"],textColor=SEV_COLOR[sev],fontName=FONT_B)
                rows.append([Paragraph(SEV_TR[sev],cs),P(str(counts[sev]),S["body"])]); r+=1
        st=Table(rows,colWidths=[80*mm,30*mm]); st.setStyle(TableStyle(stl)); E+=[st,Spacer(1,6*mm)]

    # ANA RAPOR
    if report_md:
        E+=[Paragraph("Sızma Testi Detay Raporu",S["h1"]),HRFlowable(width="100%",color=NAVY),Spacer(1,3*mm)]
        E+=md_to_flowables(report_md,S)
    elif findings:
        E+=[Paragraph("Bulgular",S["h1"]),HRFlowable(width="100%",color=NAVY),Spacer(1,3*mm)]
        for i,f in enumerate(findings,1):
            cs=ParagraphStyle("cs",parent=S["body"],textColor=SEV_COLOR.get(f["sev"],colors.grey),fontName=FONT_B)
            E+=[Paragraph(f"{i}. {f['title']}  [{SEV_TR.get(f['sev'],'')}]",cs)]
            if f.get("cvss"): E+=[P(f"CVSS: {f['cvss']}",S["small"])]
            E+=[Spacer(1,3*mm)]
    else:
        E+=[Paragraph("Bulgular",S["h1"]),HRFlowable(width="100%",color=NAVY),Spacer(1,3*mm),
            Paragraph("Bu taramada raporlanabilir bulgu tespit edilmemiştir.",S["body"])]

    if getattr(args,"osint_md","") and os.path.exists(args.osint_md):
        try: _ot=open(args.osint_md,encoding="utf-8",errors="replace").read()
        except Exception: _ot=""
        if _ot.strip():
            E+=[PageBreak(),Paragraph("OSINT — Kullanıcı Adı Keşfi",S["h1"]),HRFlowable(width="100%",color=NAVY),Spacer(1,3*mm)]
            E+=md_to_flowables(_ot,S)

    sast=load_semgrep(args.sast_json) if getattr(args,"sast_json","") and os.path.exists(args.sast_json) else []
    if sast:
        E+=[PageBreak(),Paragraph("Kod Analizi (SAST — Semgrep)",S["h1"]),HRFlowable(width="100%",color=NAVY),Spacer(1,3*mm)]
        cnt={}
        for _f in sast: cnt[_f["sev"]]=cnt.get(_f["sev"],0)+1
        _oz=", ".join(f"{SEV_TR[k]}: {cnt[k]}" for k in ["critical","high","medium","low","info"] if cnt.get(k))
        E+=[Paragraph(f"Toplam <b>{len(sast)}</b> statik kod bulgusu ({_oz}). Analiz yerelde yapıldı; kaynak kod dışarı gönderilmedi.",S["body"]),Spacer(1,4*mm)]
        for i,_f in enumerate(sast,1):
            _cs=ParagraphStyle(f"sc{i}",parent=S["body"],textColor=SEV_COLOR.get(_f["sev"],colors.grey),fontName=FONT_B)
            E+=[Paragraph(f"{i}. {_f['title']}  [{SEV_TR.get(_f['sev'],'')}]",_cs)]
            if _f.get("loc"): E+=[P("Konum: "+_f["loc"],S["small"])]
            if _f.get("tag"): E+=[P(_f["tag"],S["small"])]
            if _f.get("desc"): E+=[P(_f["desc"],S["body"])]
            E+=[Spacer(1,3*mm)]

    def footer(canvas,d):
        canvas.saveState(); canvas.setFont(FONT,7.5); canvas.setFillColor(colors.grey)
        canvas.drawString(18*mm,10*mm,f"C-Prot Siber Güvenlik · Sızma Testi Raporu · {args.firma or ''}")
        canvas.drawRightString(192*mm,10*mm,f"Sayfa {d.page}"); canvas.restoreState()
    doc.build(E,onFirstPage=footer,onLaterPages=footer)
    print(f"[+] PDF olusturuldu: {args.out}  (md_rapor={'var' if report_md else 'yok'}, sarif_bulgu={len(findings)})")

if __name__=="__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--run-dir",default=""); ap.add_argument("--firma",default="")
    ap.add_argument("--uygulama",default=""); ap.add_argument("--hedef",default="")
    ap.add_argument("--turler",default=""); ap.add_argument("--out",required=True)
    ap.add_argument("--osint-md",dest="osint_md",default="")
    ap.add_argument("--sast-json",dest="sast_json",default="")
    build(ap.parse_args())
