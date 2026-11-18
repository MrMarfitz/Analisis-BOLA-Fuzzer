# Analisis BOLA Fuzzer

Rilis aplikasi lokal **1.0.0**. [Pengoperasian dan batas produk](docs/RILIS_LOKAL.md) · [Protokol evaluasi dan baseline](docs/PROTOKOL_EVALUASI.md) · [Catatan validasi live](docs/VALIDASI_LIVE_20261117.md).

BOLA Fuzzer memeriksa apakah pengguna lain dapat membaca objek yang seharusnya privat. Tool mengambil ID objek dari akun pemilik, mengirim permintaan pembacaan yang sama dengan dua sesi, lalu menilai kecocokan objek dan atribut privat berdasarkan kebijakan akses yang dikonfigurasi. Dashboard menyajikan respons kedua akun, bukti, dan alasan keputusan.

## Menjalankan dashboard lokal

Siapkan Python 3.10 atau lebih baru. Dari folder repo, jalankan `python run_lab.py --open` atau klik dua kali `Mulai-Lab.cmd` di Windows. Biarkan terminal tetap terbuka, lalu kunjungi [dashboard](http://127.0.0.1:8081/). Launcher juga menyiapkan dua API kontrol lokal. Lab kontrol bawaan memakai pustaka standar Python.

Pilih **Lab kendaraan privat**, klik **Terapkan profil**, lalu buka **Ringkasan**. Klik **Periksa kesiapan target**, kemudian **Jalankan pengujian**. Form terdiri atas bagian **Target API**, **Akun pengujian**, **Objek & otorisasi**, dan **Ringkasan**. Pada hasil, lihat keputusan, identitas sesi, serta ID dan atribut privat pada kedua respons. Gunakan profil **Kontrol objek publik** untuk melihat bagaimana dua respons HTTP 200 dapat menghasilkan keputusan berbeda. [Panduan uji lengkap](PANDUAN_UJI.md)

Konfigurasi dapat diekspor melalui tautan unduhan JSON dan diimpor kembali tanpa menyimpan password atau label acuan. Hasil menyediakan unduhan HTML, Markdown, laporan akademik, serta JSON bukti lengkap dengan konfigurasi tanpa password, hash source, jumlah permintaan, dan waktu eksekusi. Laporan bertahan di folder `reports` setelah halaman ditutup.

## Peran scanner, crAPI, dan Docker

Dashboard browser dan engine Python merupakan BOLA Fuzzer. crAPI adalah aplikasi target yang diuji. Docker menjalankan crAPI beserta database dan layanan pendukungnya pada instalasi lab lokal ini. Kontrol sintetis bawaan berjalan tanpa Docker; scanner juga tidak membutuhkan crAPI ketika menguji API target lain yang sesuai dengan konfigurasi dan cakupannya.

Halaman crAPI tidak harus terbuka di browser, tetapi server target harus tetap berjalan. Status **Engine terhubung** hanya menunjukkan backend scanner aktif, bukan kesiapan target. **Pengujian selesai** menunjukkan proses selesai; keputusan dan bukti tetap harus diperiksa. Hasil **Tidak terindikasi pada kasus ini** bukan pernyataan seluruh aplikasi aman, sedangkan **Belum disimpulkan** berarti bukti atau pelaksanaan belum memadai.

## Menguji crAPI

Siapkan [OWASP crAPI](https://github.com/OWASP/crAPI) di Docker lokal dengan dua akun uji dan kendaraan yang terdaftar. Untuk instalasi yang memakai nama container standar dan port loopback 8888, jalankan `python run_crapi_lab.py` atau `Mulai-crAPI-Lab.cmd` untuk menyalakan container yang sudah tersedia. Launcher tidak memasang crAPI atau membuat akun baru. Di dashboard, pilih **crAPI · lokasi kendaraan privat**, klik **Terapkan profil**, lalu isi kredensial dua akun uji milik sendiri. Profil mengisi pemetaan di bawah dan mengosongkan kredensial. **Target kustom** tetap tersedia untuk pemetaan lain dan mempertahankan isian sebelumnya.

| Kolom | Nilai untuk lokasi kendaraan |
|---|---|
| Endpoint login | `/identity/api/auth/login` |
| Field pengguna dan lokasi token | `email` dan `token` |
| Endpoint daftar objek | `/identity/api/v2/vehicle/vehicles` |
| Lokasi ID dalam daftar | `$[0].uuid` |
| Endpoint pembacaan | `/identity/api/v2/vehicle/{vehicleId}/location` |
| Parameter dan lokasi identitas objek | `vehicleId` dan `$.carId` |
| Kebijakan | Privat |
| Atribut privat | `$.email, $.vehicleLocation` |
| Endpoint identitas sesi dan lokasi ID | `/identity/api/v2/user/dashboard` dan `$.id` |

Periksa kepemilikan objek dan kebijakan target sebelum menarik kesimpulan. Simpan akun uji, token, konfigurasi privat, dataset penelitian, dan laporan di luar riwayat Git. Jalankan pengujian pada sistem yang lo kelola atau diizinkan untuk diuji.

## Verifikasi fungsi melalui dashboard — 9 November 2026

| Skenario | Hasil yang diamati |
|---|---|
| Lokasi kendaraan privat pada crAPI lokal | Indikasi BOLA; sesi berbeda terverifikasi, dan akun B menerima identitas objek serta atribut privat yang sama dengan respons A. |
| Kontrol HTTP 200 berisi penolakan | Tidak terindikasi pada kasus ini; atribut objek privat tidak tersedia pada respons B. |
| Kontrol objek publik | Tidak terindikasi pada kasus ini; akses objek sesuai kebijakan publik. |

Ketiga skenario selesai tanpa keputusan tidak konklusif. Pemeriksaan ini memverifikasi fungsi pada skenario tersebut, bukan evaluasi utama dataset, ukuran akurasi keseluruhan, atau klaim generalisasi. Bukti sesi lokal disimpan terpisah dari repo. Dashboard ini menguji pembacaan GET/JSON dan memerlukan pemetaan objek serta kebijakan yang ditinjau.

## Pengujian kode

```text
python -m unittest discover -s tests -q
node tests/test_dashboard_ui.cjs
```

Node.js diperlukan untuk tes antarmuka. Instal dependensi di `requirements.txt` bila memakai konfigurasi YAML atau pytest.
