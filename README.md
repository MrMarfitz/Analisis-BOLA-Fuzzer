# Analisis BOLA Fuzzer

BOLA Fuzzer memeriksa apakah pengguna lain dapat membaca objek yang seharusnya privat. Tool mengambil ID objek dari akun pemilik, mengirim permintaan pembacaan yang sama dengan dua sesi, lalu menilai kecocokan objek dan atribut privat berdasarkan kebijakan akses yang dikonfigurasi. Dashboard menyajikan respons kedua akun, bukti, dan alasan keputusan.

## Menjalankan dashboard lokal

Siapkan Python 3.10 atau lebih baru. Dari folder repo, jalankan `python run_lab.py --open` atau klik dua kali `Mulai-Lab.cmd` di Windows. Biarkan terminal tetap terbuka, lalu kunjungi [dashboard](http://127.0.0.1:8081/). Launcher juga menyiapkan dua API kontrol lokal. Demo bawaan memakai pustaka standar Python.

Pilih **Lab kendaraan privat**, klik **Gunakan konfigurasi**, lalu ikuti formulir sampai **Jalankan pengujian**. Pada hasil, lihat status **Indikasi BOLA**, identitas sesi, serta ID dan VIN pada kedua respons. Gunakan konfigurasi **Kontrol objek publik** untuk melihat bagaimana dua respons HTTP 200 dapat menghasilkan keputusan berbeda. [Panduan demo lengkap](PANDUAN_DEMO.md)

## Menguji crAPI

Siapkan [OWASP crAPI](https://github.com/OWASP/crAPI) di Docker lokal dengan dua akun uji dan kendaraan yang terdaftar. Untuk instalasi yang memakai nama container standar dan port loopback 8888, jalankan `python run_crapi_demo.py` atau `Mulai-crAPI-Demo.cmd` untuk menyalakan container yang sudah tersedia. Di dashboard, pilih **API sendiri · isi manual** dan isi target `http://127.0.0.1:8888` serta kredensial akun uji milik sendiri.

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

## Pengujian kode

```text
python -m unittest discover -s tests -q
node tests/test_dashboard_ui.cjs
```

Node.js diperlukan untuk tes antarmuka. Instal dependensi di `requirements.txt` bila memakai konfigurasi YAML atau pytest.
