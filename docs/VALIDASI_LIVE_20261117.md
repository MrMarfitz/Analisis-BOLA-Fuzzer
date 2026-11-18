# Catatan validasi live dashboard

## Tujuan

Catatan ini membedakan uji aplikasi yang benar-benar mengirim HTTP ke crAPI lokal dari uji kontrol sintetis. Ini bukan hasil evaluasi utama, ground truth, atau klaim generalisasi.

## Lingkungan yang diuji

| Komponen | Nilai terverifikasi |
| --- | --- |
| Dashboard dan engine | BOLA Fuzzer 1.0.0 pada `http://127.0.0.1:8081` |
| Target | OWASP crAPI lokal pada `http://127.0.0.1:8888` |
| Runtime identity crAPI | `crapi/crapi-identity:1.1.6`, digest `sha256:51b4cdd1a88f24e00e66c4c37735e7f8adbb98071252f3cf4f6dda9e00671aed` |
| Jalur uji | GET `/identity/api/v2/vehicle/{vehicleId}/location` |
| Kebijakan yang dikonfigurasi | Privat; objek dipilih dari sesi pemilik, kemudian dibaca ulang dari sesi pengguna lain |

Image identity dipin ke rilis 1.1.6 setelah image `latest` yang sebelumnya digunakan terbukti menggantung ketika jalur lokasi kendaraan dipanggil. Tidak ada reset volume, pembuatan akun, atau hasil contoh yang digunakan untuk uji ini.

## Hasil eksekusi

Eksekusi dashboard pada 17 November 2026 menghasilkan satu kasus dari target crAPI lokal.

| Pengukuran | Nilai |
| --- | --- |
| Permintaan HTTP tercoba | 7 |
| Waktu engine | 3,147092 detik |
| Sesi A dan B | Berbeda dan lolos preflight |
| Hasil engine | `Potential BOLA` / `Indikasi BOLA` |
| Dasar indikasi | Sesi B menerima ID objek pemilik dan atribut privat yang sama dengan respons sesi A |

Laporan yang dihasilkan oleh engine:

- `reports/bola-report-20261117-204014-029241-e2bd91fb.html`
- `reports/bola-report-20261117-204014-029241-e2bd91fb.md`
- `reports/academic-bola-report-20261117-204014-033681-0c7d2ffb.md`
- `reports/run-record-017c7686c73f41a49a08f4911857a42f.json`

Unduhan HTML dari tombol dashboard telah dibandingkan byte-per-byte dengan laporan sumber engine: SHA-256 `D44CE5A3EBC3AE3DC630792FEA89642F0D7E435B490BC495DB17FA943DD112F5` (4.283 byte).

## Reproduksi

1. Nyalakan Docker Desktop lalu jalankan `Mulai-crAPI-Lab.cmd`; launcher hanya menyalakan container yang sudah terpasang dan memeriksa health check.
2. Buka dashboard, pilih profil **crAPI · lokasi kendaraan privat**, lalu isi dua akun uji yang sudah terdaftar pada instance lokal.
3. Klik **Periksa kesiapan target**. Preflight harus lulus autentikasi A dan B, identitas dua sesi, serta pembacaan objek pemilik. Preflight tidak mengirim pembacaan silang.
4. Klik **Jalankan pengujian**. Hasil, bukti kedua respons, laporan HTML/Markdown, laporan akademik, dan rekaman JSON harus muncul pada tab **Hasil pengujian**.

## Batas interpretasi

Keputusan aplikasi adalah indikasi teknis berdasarkan pemetaan kebijakan privat dan bukti respons. Label ground truth penelitian tetap harus dinilai secara independen berdasarkan kebijakan otorisasi runtime dan bukti pendukung. Kasus yang bukti atau runtime-nya tidak cukup harus dicatat sebagai tidak konklusif, bukan dipaksa menjadi BOLA atau non-BOLA.
