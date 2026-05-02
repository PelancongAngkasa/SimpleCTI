# CTI Log Collector (Docker-based)

## Deskripsi
CTI Log Collector merupakan aplikasi sederhana berbasis Python yang digunakan untuk melakukan pengumpulan dan analisis log server secara otomatis. Sistem ini dirancang untuk mendeteksi aktivitas mencurigakan berdasarkan log web server (Apache/Nginx) dan sistem autentikasi, kemudian melakukan enrichment menggunakan threat intelligence dari AlienVault OTX.

Hasil analisis akan diklasifikasikan berdasarkan tingkat risiko dan dikirimkan sebagai notifikasi melalui Telegram.

---

## Tujuan
- Mengotomatisasi proses deteksi aktivitas mencurigakan dari log server
- Mengurangi pekerjaan manual pada tim keamanan siber (CTI)
- Memberikan notifikasi cepat terhadap potensi serangan
- Menyediakan dasar integrasi ke sistem SIEM (seperti Wazuh)

---

## Fitur Utama
- Parsing log dari:
  - Apache (Ubuntu/CentOS)
  - Nginx
  - Auth log (`/var/log/auth.log`)
- Deteksi aktivitas mencurigakan:
  - Brute force (Failed password, Invalid user)
  - Scanning tools (nmap, sqlmap)
  - Server error (500)
- Ekstraksi dan validasi IP publik
- Enrichment IP menggunakan AlienVault OTX
- Klasifikasi tingkat risiko:
  - LOW
  - MEDIUM
  - HIGH
  - CRITICAL
- Notifikasi otomatis ke Telegram
- Cache hasil OTX (menghindari request berulang)
- Output laporan dalam format CSV

---

## Arsitektur Sistem
Log Server → Collector → Filtering → Enrichment (OTX) → Scoring → Alert Telegram

Aplikasi dijalankan dalam container Docker dan membaca log server host menggunakan volume mount.

---

## Teknologi yang Digunakan
- Python 3
- Docker
- AlienVault OTX API
- Telegram Bot API

---

## Persyaratan
- Docker terinstall pada server
- Akses ke direktori log:
  - `/var/log/nginx`
  - `/var/log/apache2` atau `/var/log/httpd`
- API Key AlienVault OTX
- Token Bot Telegram

---

## Konfigurasi

Buat file `.env`:
OTX_API_KEY=your_otx_api_key
TELEGRAM_TOKEN=your_telegram_bot_token
TELEGRAM_CHAT_ID=your_chat_id

---

## Cara Menjalankan

### 1. Build Docker Image
docker build -t cti-collector .

### 2. Jalankan Container
docker run -d
--name cti-collector
--user root
--env-file .env
-v /var/log:/var/log:ro
-v $(pwd):/app
--restart unless-stopped
cti-collector

---

## Cara Kerja Sistem
1. Sistem membaca log server secara berkala
2. Melakukan filtering terhadap aktivitas mencurigakan
3. Mengekstrak IP address dari log
4. Memvalidasi IP publik
5. Mengambil data reputasi dari AlienVault OTX
6. Mengklasifikasikan tingkat risiko
7. Mengirim alert ke Telegram (untuk HIGH & CRITICAL)
8. Menyimpan hasil ke:
   - `cache.json`
   - `report.csv`

---

## Output

### 1. Console
Menampilkan hasil analisis secara langsung

### 2. Telegram
Notifikasi untuk aktivitas berisiko tinggi

### 3. File
- `cache.json` → penyimpanan cache OTX
- `report.csv` → laporan hasil analisis

---

## Klasifikasi Risiko

| Level     | Kriteria                          |
|----------|----------------------------------|
| LOW      | Aktivitas kecil                  |
| MEDIUM   | Banyak request mencurigakan      |
| HIGH     | Terindikasi di OTX               |
| CRITICAL | OTX + frekuensi tinggi           |

---

## Keamanan
- Akses log bersifat read-only (`:ro`)
- Tidak mengubah file log server
- Token disimpan dalam file `.env`

---

## Keterbatasan
- Masih menggunakan metode polling (belum real-time)
- Belum mendukung korelasi antar event
- Belum terintegrasi langsung dengan SIEM

---

## Pengembangan Selanjutnya
- Implementasi real-time log streaming
- Integrasi dengan Wazuh / SIEM
- Dashboard monitoring (Streamlit)
- Penambahan GeoIP dan ASN lookup
- Alert deduplication dan rate limiting

---

## Kontributor
PelancongAngkasa(Main Developer)

---

## Catatan
Aplikasi ini dikembangkan sebagai solusi lightweight untuk membantu tim dengan sumber daya terbatas dalam melakukan monitoring keamanan berbasis log secara otomatis.
