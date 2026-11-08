# Atribusi dan deklarasi

## Komponen pihak ketiga

| Komponen | Pemakaian | Lisensi |
| --- | --- | --- |
| FastAPI | API aplikasi | MIT |
| Uvicorn | Server ASGI | BSD-3-Clause |
| ReportLab | Laporan PDF | BSD-3-Clause |
| cryptography (PyCA) | Membaca sertifikat X.509 | Apache-2.0 / BSD-3-Clause |
| OpenSSL 3.5 | Probe TLS dan grup hybrid | Apache-2.0 |
| nginx | PQC Gateway dan layanan lab | BSD-2-Clause |
| OpenSSH | Layanan SSH lab | Lisensi BSD |
| Alpine Linux, Python | Image dasar container | Lisensi masing-masing |
| pytest, HTTPX, cyclonedx-python-lib | Pengujian dan validasi CBOM | MIT, BSD-3-Clause, Apache-2.0 |

Standar yang dirujuk: NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), CycloneDX 1.6, teorema Mosca. OID Falcon diambil dari daftar algoritma open-quantum-safe oqs-provider.

Rujukan latar masalah: S. Chawande, "Quantum computing threats to cybersecurity protocols", World Journal of Advanced Engineering Technology and Sciences, 2025, 15(02), 707-720. DOI 10.30574/wjaets.2025.15.2.0546.

## Deklarasi karya

- Tidak ada karya pre-existing milik tim yang dipakai sebagai dasar. Kode dibuat selama periode program.
- Claude Code (Anthropic) dipakai sebagai alat bantu pengembangan.
- Semua data di lab dan `demo/qshield.db` adalah data tiruan. Tidak ada data pribadi atau sistem nyata.
