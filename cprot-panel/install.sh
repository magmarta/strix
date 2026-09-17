#!/usr/bin/env bash
# ============================================================================
#  C-Prot Strix Pentest Panel — tek komut kurulum (Debian 12/13, root ile)
#  Kullanim:  sudo bash cprot-panel/install.sh
# ============================================================================
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Bu betik root ile calistirilmali."; exit 1; }
SRC="$(cd "$(dirname "$0")" && pwd)"

echo "[1/6] Docker kuruluyor..."
if ! command -v docker >/dev/null 2>&1; then curl -fsSL https://get.docker.com | sh; fi
systemctl enable --now docker

echo "[2/6] Strix kuruluyor (binary + sandbox imaji)..."
if ! command -v strix >/dev/null 2>&1 && [ ! -x "$HOME/.strix/bin/strix" ]; then
  curl -sSL https://strix.ai/install | bash
fi
ln -sf "$HOME/.strix/bin/strix" /usr/local/bin/strix

echo "[3/6] Python + font bagimliliklari + Sherlock (OSINT)..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  python3-flask python3-reportlab python3-markdown fonts-dejavu-core poppler-utils >/dev/null
# Sherlock (kullanici adi OSINT) — Debian 13 paketi, yoksa pipx
if ! command -v sherlock >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sherlock >/dev/null 2>&1 || {
    apt-get install -y -qq pipx >/dev/null 2>&1 && pipx install sherlock-project >/dev/null 2>&1 || true
  }
fi
# Semgrep (kod analizi / SAST) — yerel calisir, kaynak kod disari cikmaz
if ! command -v semgrep >/dev/null 2>&1; then
  apt-get install -y -qq pipx >/dev/null 2>&1 && pipx install semgrep >/dev/null 2>&1 || pip3 install --quiet --break-system-packages semgrep >/dev/null 2>&1 || true
fi

echo "[4/6] Panel + CLI dosyalari..."
mkdir -p /opt/pentest/lib /opt/pentest/webpanel/templates /etc/pentest /root/pentests
install -m755 "$SRC/saldir"                         /opt/pentest/saldir
install -m755 "$SRC/lib/strix_rapor.py"             /opt/pentest/lib/strix_rapor.py
install -m755 "$SRC/webpanel/app.py"                /opt/pentest/webpanel/app.py
install -m755 "$SRC/webpanel/runner.py"             /opt/pentest/webpanel/runner.py
install -m644 "$SRC/webpanel/templates/index.html"  /opt/pentest/webpanel/templates/index.html
install -m644 "$SRC/webpanel/templates/login.html"  /opt/pentest/webpanel/templates/login.html
ln -sf /opt/pentest/saldir /usr/local/bin/saldir

echo "[5/6] Ortam + systemd servisi..."
if [ ! -f /etc/pentest/strix.env ]; then
  printf 'STRIX_LLM="anthropic/claude-sonnet-4-6"\nLLM_API_KEY=""\n' > /etc/pentest/strix.env
  chmod 600 /etc/pentest/strix.env
fi
install -m644 "$SRC/systemd/strix-panel.service" /etc/systemd/system/strix-panel.service
systemctl daemon-reload
systemctl enable --now strix-panel

echo "[6/6] Tamamlandi."
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo "------------------------------------------------------------"
echo "  Panel : http://${IP:-<sunucu-ip>}/    (kullanici: admin / sifre: admin)"
echo "  CLI   : saldir --help"
echo "  ONEMLI: Anahtari girin -> /etc/pentest/strix.env  (LLM_API_KEY)"
echo "------------------------------------------------------------"
