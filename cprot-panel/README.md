# C-Prot Strix Pentest Panel

[Strix](https://github.com/usestrix/strix) tabanlı, **Türkçe** sızma testi kontrol paneli ve CLI'ı.
Web arayüzünden sihirbazla hedef ve saldırı türlerini seçip otonom pentest çalıştırır, sonucu
**Türkçe PDF rapor** olarak indirir.

## Özellikler
- 🖥️ **Web paneli** (port 80, `admin/admin`) — adım adım sihirbaz, canlı log, geçmiş taramalar
- ⌨️ **`saldir` CLI** — Türkçe komut arayüzü
- 🎯 **Saldırı türleri:** `ip, port, web, zafiyet, kimlik, api, ssl, dizin, arp, zehirleme, dos, hepsi`
- 🔑 **Kimlik doğrulamalı test** — kullanıcı adı/parola ile authenticated saldırı
- 📄 **Türkçe PDF rapor** — DejaVu fontu (tam Türkçe karakter), Strix markdown raporu render edilir
- 🤖 **LLM:** Anthropic Claude (varsayılan `claude-sonnet-4-6`)

## Kurulum (yeni Debian VM)
```bash
git clone https://github.com/magmarta/strix.git
cd strix
sudo bash cprot-panel/install.sh
# Ardindan API anahtarini girin:
sudo sed -i 's|LLM_API_KEY=.*|LLM_API_KEY="sk-ant-..."|' /etc/pentest/strix.env
```
Panel: `http://<sunucu-ip>/` — `admin` / `admin`

## CLI kullanımı
```bash
saldir --ip 192.168.1.10 --url http://192.168.1.10:8080 --app "webapp" --firma "ACME A.Ş." \
       --saldiriturleri web,port,zafiyet,kimlik --kullanici admin --parola admin \
       --mod standard --butce 6
```
Rapor: `/root/pentests/<firma>/<tarih>-<uygulama>/Rapor_*.pdf`

## Bileşenler
| Yol | Açıklama |
|-----|----------|
| `cprot-panel/saldir` | Türkçe CLI (saldırı türü → Strix talimatı) |
| `cprot-panel/lib/strix_rapor.py` | Türkçe PDF üreteci (SARIF + markdown) |
| `cprot-panel/webpanel/` | Flask web paneli (app.py, runner.py, templates) |
| `cprot-panel/systemd/` | `strix-panel.service` |
| `cprot-panel/install.sh` | Tek komut kurulum |

## Notlar
- `arp`/`zehirleme` (L2/MITM) sandbox'ta NET_ADMIN/host-ağı gerektirir; sınırlı olabilir.
- Anthropic hesabında API kredi bakiyesi gerekir (Plans & Billing).
- Yalnızca **yetkili** sızma testi için kullanın.
