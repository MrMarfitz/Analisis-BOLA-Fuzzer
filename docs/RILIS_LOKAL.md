# BOLA Fuzzer 1.0.0

Rilis aplikasi lokal untuk pengujian BOLA horizontal pada pembacaan GET/JSON, sesuai cakupan Bab I proposal. Pengguna memasukkan dua akun sah, pemetaan objek, dan kebijakan yang sudah ditinjau. Aplikasi mengirim HTTP nyata dan menyajikan hasil serta bukti. Kebijakan bisnis tetap ditetapkan pengguna.

## Menjalankan aplikasi

Ekstrak seluruh paket ZIP ke satu folder. Gunakan Python 3.10 atau lebih baru. Klik `Mulai-Lab.cmd` di Windows atau jalankan `python run_lab.py --open`. Buka http://127.0.0.1:8081/ dan biarkan proses launcher tetap berjalan. Demo bawaan memakai pustaka standar Python tanpa Docker. Launcher dapat memakai Python lingkungan Codex jika tersedia, lalu mencoba Python terpasang.

Jika port 8081 masih menjalankan versi lama, tutup proses launcher lama lalu jalankan paket ini. Launcher tidak mematikan proses lain. Status backend versi baru menampilkan `1.0.0`.

## Pengoperasian

1. Pilih profil target lalu klik **Terapkan profil**. Profil crAPI mengisi pemetaan lokasi kendaraan dan mengosongkan akun agar kredensial lab sintetis tidak terbawa.
2. Untuk crAPI, isi dua akun yang benar-benar terdaftar pada instance lokal. Pastikan container aktif. Docker Desktop saja belum menjamin container berjalan. Paket ini tidak menyertakan instalasi crAPI, akun privat, atau database peneliti.
3. Periksa bagian **Objek & otorisasi**, lalu buka **Ringkasan**.
4. Klik **Periksa kesiapan target** untuk memeriksa login, perbedaan identitas sesi, sumber objek, dan pembacaan pemilik. Pemeriksaan ini belum mencoba akses silang dan belum menetapkan BOLA.
5. Klik **Jalankan pengujian**. Pada hasil, baca keputusan, bukti dua respons, identitas sesi, jumlah permintaan, dan waktu. Kegagalan layanan atau login tidak menjadi bukti aman.
6. Buka **Berkas laporan lokal** untuk mengunduh HTML, Markdown, laporan akademik, atau JSON rekaman eksekusi. JSON memuat konfigurasi tanpa password, bukti, biaya, dan hash kode. Berkas juga tersimpan di folder `reports`.

**Ekspor konfigurasi** menghasilkan tautan **Unduh konfigurasi JSON** yang menyimpan pemetaan dan identitas akun tanpa password atau label acuan. **Impor konfigurasi** mengembalikan isian dan meminta password diisi ulang. Periksa ulang label secara independen sebelum evaluasi. Ekspor bukan cadangan hasil; hasil dan formulir aktif berada di memori halaman. Laporan di disk bertahan setelah reload.

## crAPI dan Docker

Scanner terdiri atas dashboard dan engine Python. crAPI adalah target lab terpisah; Docker menjalankan layanan target. Halaman crAPI tidak perlu tetap terbuka di browser. `Mulai-crAPI-Demo.cmd` menyalakan kembali container crAPI yang telah dipasang dengan nama standar dan port loopback. Launcher tidak memasang Docker, mengunduh image, membuat akun, atau menghapus data.

## Status rilis dan penelitian

Paket ini adalah rilis aplikasi lokal dengan cakupan terbatas yang disebutkan di atas. Kesiapan rilis ditentukan dari pemeriksaan fungsi dan alur penggunaan. Persetujuan sempro, penerimaan kebaruan, dan evaluasi utama merupakan proses penelitian terpisah. Tidak ada klaim bahwa seluruh jenis BOLA, format respons, atau aturan bisnis dapat diuji otomatis.

Pembandingan ilmiah dijalankan melalui CLI yang dijelaskan dalam `PROTOKOL_EVALUASI.md`. Tidak diperlukan untuk menjalankan scan manual. Mode evaluasi utama memerlukan rekaman tinjauan label manusia. Baseline diagnostik bukan pengganti otomatis untuk metode terdahulu yang mungkin diminta dosen.
