# QShield

Platform kesiapan kuantum untuk satuan TNI AD. Q-Shield memindai aset, memetakan kriptografi yang rentan terhadap komputer kuantum, memberi skor risiko, lalu memasang proteksi hybrid post-quantum lewat gateway tanpa mengubah aplikasi lama.

Karya untuk Kartika Cyber Hackathon 2026, kategori Dukungan Teknologi.

## Masalah

Data rahasia yang dienkripsi dengan RSA/ECC hari ini sudah terancam: lawan bisa menyadapnya sekarang dan mendekripsinya saat komputer kuantum siap (Harvest-Now-Decrypt-Later, HNDL). Satuan tidak bisa merencanakan migrasi tanpa tahu di mana RSA/ECC dipakai.

## Siklus kerja

1. **Temukan:** scanner membaca TLS, SSH, sertifikat, kode, dan konfigurasi.
2. **Nilai:** setiap aset diberi skor risiko dan diuji dengan teorema Mosca.
3. **Lindungi:** aset HTTPS dibungkus gateway hybrid `X25519MLKEM768`.
4. **Buktikan:** scan ulang memverifikasi handshake hybrid dan benchmark mengukur biayanya.

## Menjalankan lab

Butuh Docker. Semua layanan lab adalah tiruan lokal dan port hanya terikat ke `127.0.0.1`.

```
docker compose up -d --build
```

Buka http://localhost:8000, lalu:

1. Klik **Jalankan scan**.
2. Klik **Portal Internal**, lalu **Terapkan PQC Gateway**. Skor satuan naik.
3. Klik **Jalankan benchmark** untuk melihat overhead hybrid dibanding klasik.
4. Unduh **Ekspor CBOM** dan **Laporan PDF**.

Untuk mereset lab: `docker compose down -v`.

## Isi lab "Satuan Kartika-01"

| Aset | Kondisi | Tujuan demo |
| --- | --- | --- |
| Portal Internal | TLS 1.3, RSA-2048, X25519 | Rentan HNDL, bisa pakai gateway |
| API Logistik Lama | TLS 1.2, RSA-1024 | Legacy, masuk roadmap migrasi |
| Server Admin SSH | OpenSSH, ECDSA, tanpa kex hybrid | Perlu update software |
| Repo Aplikasi Satuan | Kode RSA/ECC dan private key dummy | Scanner kode dan konfigurasi |
| Layanan PQ-Ready | TLS 1.3 hybrid | Pembanding yang sudah aman |

Semua kunci dibuat saat container start. Tidak ada private key di repository ini.

## Arsitektur

```
Repo kode/konfigurasi --> M2 Code Scanner --+
                                            +--> M3 CBOM + Risk Engine --> M4 Dashboard + PDF
Layanan jaringan -------> M1 Network Scanner+                                   |
      ^                                                                         | terapkan
      |                                                                         v
      +------------------------- dipasang di depan layanan ---------------- M5 PQC Gateway
```

- **M1 Network Scanner** (`qshield/scanners/tls.py`, `ssh.py`): probe TLS memakai OpenSSL 3.5 agar bisa menguji grup ML-KEM; probe SSH membaca `SSH_MSG_KEXINIT` tanpa login.
- **M2 Code and Config Scanner** (`qshield/scanners/code.py`): aturan untuk Python, Java, JS/TS, Go, nginx, OpenSSH, dan file private key. Isi kunci tidak pernah disimpan.
- **M3 CBOM and Risk Engine** (`qshield/risk.py`, `cbom.py`): CBOM CycloneDX 1.6, divalidasi terhadap skema resmi dalam test.
- **M4 Dashboard dan Laporan** (`qshield/static/`, `report.py`): tanpa CDN, jadi jalan offline.
- **M5 PQC Gateway** (`gateway/`): nginx + OpenSSL 3.5. Aplikasi hanya menulis file route; watcher di container gateway memvalidasi dengan `nginx -t` lalu reload. Status "aktif" hanya diberikan setelah handshake hybrid nyata berhasil.
- **M6 Benchmark** (`qshield/gateway.py`): median waktu dan byte handshake, klasik dibanding hybrid.

## Model risiko

```
Risk = 100 x (0.40 A + 0.30 S + 0.20 E + 0.10 M)
Rentan menurut Mosca jika X + Y > Z
```

| Faktor | Nilai |
| --- | --- |
| A algoritma | kex RSA/ECC/DH = 1.0; AES-128 = 0.3; hybrid = 0.0 |
| S sensitivitas | rahasia = 1.0; internal = 0.5; publik = 0.1 |
| E eksposur | internet = 1.0; antar-satuan = 0.6; LAN = 0.3 |
| M migrasi | gateway = 0.4; update = 0.7; legacy = 1.0 |
| X masa rahasia (default) | rahasia = 10; internal = 5; publik = 0 tahun |
| Y lama migrasi (default) | gateway = 1; update = 2; legacy = 5 tahun |
| Z | tahun kuantum relevan (default 2030) dikurangi tahun ini |

Aset dengan A = 0 berisiko 0, karena tidak ada kerahasiaan yang rentan. Skor satuan adalah 100 dikurangi rata-rata risiko berbobot sensitivitas.

Bobot, X, Y, dan tahun Z bisa diubah di bagian Pengaturan skor, dan berlaku pada scan berikutnya. X dan Y hanya menentukan label rentan Mosca, bukan angka risiko. Nilai default X dan Y adalah asumsi awal, jadi catat sumber nilai pengganti di kolom yang tersedia. Sumber itu ikut tampil di detail aset dan laporan PDF.

## Keamanan alat

- Hanya target di allowlist yang dipindai, dan pendaftaran wajib konfirmasi izin.
- Target alamat publik aktif di `docker-compose.yml` lewat `QSHIELD_ALLOW_PUBLIC=1`. Tanpa variabel itu, alamat publik ditolak saat pendaftaran dan saat scan. Daftarkan hanya sistem milik sendiri atau yang izinnya sudah dimiliki.
- Scan kode dibatasi ke folder di bawah `QSHIELD_REPO_ROOT`.
- Input host divalidasi agar tidak bisa menyisipkan konfigurasi nginx.
- Aplikasi tidak memegang Docker socket.

Dashboard lab tidak punya login. Jangan membuka port-nya ke jaringan. Untuk publik, gunakan mode demo di bawah. Untuk jaringan bersama, atur `QSHIELD_API_TOKEN`.

## Demo publik untuk juri

Mode baca-saja menampilkan hasil scan lab yang tersimpan di `demo/qshield.db` dan menolak semua scan serta perubahan.

```
docker compose -f docker-compose.demo.yml up -d --build
```

Untuk memperbarui snapshot setelah menjalankan lab:

```
docker compose cp qshield:/data/qshield.db demo/qshield.db
```

## Konfigurasi

| Variabel | Fungsi |
| --- | --- |
| `QSHIELD_DB` | Lokasi database SQLite |
| `QSHIELD_READ_ONLY` | `1` untuk mode demo baca-saja |
| `QSHIELD_API_TOKEN` | Token wajib untuk semua perubahan |
| `QSHIELD_ALLOW_PUBLIC` | `1` untuk mengizinkan target alamat publik |
| `QSHIELD_REPO_ROOT` | Folder induk target kode |
| `QSHIELD_GATEWAY_CONF` | Folder route yang dibaca gateway |
| `QSHIELD_GATEWAY_HOST` | Nama host gateway dari sisi aplikasi |
| `QSHIELD_GATEWAY_PORT_START` | Port awal gateway; tersedia 10 port |
| `QSHIELD_OPENSSL` | Lokasi binary OpenSSL 3.5+ |
| `QSHIELD_SEED` | File JSON target awal |

## Pengujian

```
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements-dev.txt
.venv/Scripts/python -m pytest tests
.venv/Scripts/python tests/e2e_lab.py
```

`tests/e2e_lab.py` butuh lab yang sedang berjalan.

## Batasan yang diketahui

- Hybrid melindungi kerahasiaan dari HNDL. Sertifikat tetap klasik sampai CA mendukung ML-DSA.
- Jalur dari gateway ke layanan asal tetap klasik, jadi keduanya harus berada di segmen tepercaya.
- Selama akses langsung ke layanan belum ditutup firewall, trafik lewat jalur itu tetap rentan. Dashboard menampilkannya sebagai temuan.
- Gateway hanya menangani HTTP(S). VPN IPsec, radio taktis, dan HSM di luar lingkup.
- Scanner kode berbasis aturan, jadi bisa melewatkan pemakaian tidak langsung dan tidak menggantikan audit manual.
- Waktu pada benchmark mencakup start proses `openssl`. Selisih waktu kecil tertutup noise; angka byte adalah ukuran yang presisi.
- Tahun kuantum 2030 adalah asumsi yang masih diperdebatkan.

## Atribusi

Lihat [ATTRIBUTION.md](ATTRIBUTION.md).
