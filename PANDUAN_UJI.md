# BOLA Fuzzer untuk uji langsung sempro

Aplikasi web lokal ini sudah terhubung ke engine Python. Menekan Jalankan pengujian mengirim HTTP nyata ke API target. Tidak ada angka temuan contoh, timer untuk menghasilkan hasil, atau ketergantungan CDN pada tampilan baru.

## Mulai di laptop ini

1. Klik dua kali **Mulai-Lab.cmd**. Alternatif: jalankan `python run_lab.py --open` dengan Python 3.10 atau lebih baru dari folder aplikasi.
2. Biarkan jendela launcher tetap aktif. Buka http://127.0.0.1:8081/ jika browser belum terbuka.
3. Pastikan status Engine terhubung. Ini memverifikasi dashboard, bukan menjamin seluruh API target siap.

Launcher memakai Python bawaan lingkungan Codex jika tersedia, kemudian mencoba py atau python pada PATH. Untuk lab kontrol bawaan, modul yang dibutuhkan berasal dari pustaka standar Python; tidak perlu npm, Tailwind CDN, atau pemasangan dependensi tambahan. API lab memakai data sintetis dan dua akun uji yang sudah tersedia dalam source fixture.

| Layanan | Alamat | Kegunaan |
| --- | --- | --- |
| Dashboard | http://127.0.0.1:8081/ | Form, hasil dan evaluasi |
| Lab kendaraan | http://127.0.0.1:8890/ | Kebocoran objek privat yang sengaja disiapkan |
| Lab kontrol | http://127.0.0.1:8899/ | Akses publik dan envelope penolakan HTTP 200 |

Port lab kendaraan dipisahkan dari port crAPI. Launcher memeriksa identitas layanan sebelum memakai port yang sudah aktif; ia tidak menghentikan proses lain. Ctrl+C menghentikan layanan yang dimulai launcher itu. Layanan yang sebelumnya aktif tetap berjalan.

## Uji pertama dari awal sampai bukti

1. Pada tab Konfigurasi, pilih **Lab kendaraan privat** lalu **Terapkan profil**.
2. Bagian Target API sudah terisi ke 127.0.0.1:8890. Buka Akun pengujian.
3. Akun A dan B adalah akun sintetis berbeda. Buka Objek & otorisasi.
4. Pemetaan objek sudah terisi: daftar kendaraan pemilik, ID kendaraan, pembacaan target, kebijakan privat, atribut VIN, dan identitas pengguna dari daftar terfilter. Buka Ringkasan.
5. Buka Ringkasan, periksa target dan kebijakan; tidak ada password atau token ditampilkan. Klik **Jalankan pengujian**.
6. Tunggu respons engine. Tab Hasil pengujian menampilkan **Indikasi BOLA**, objek veh_1021, dan kedua respons HTTP 200. ID serta VIN yang sama dapat dibaca oleh dua pengguna berbeda.
7. Buka **Alasan teknis dari engine**, **Lihat respons JSON**, dan **Permintaan reproduksi curl** jika diperlukan. Field ringkasan adalah bukti, bukan pengganti dasar kepemilikan dan kebijakan.
8. Buka **Berkas laporan lokal** untuk melihat lokasi laporan. Lokasi relatif terhadap folder aplikasi; buka folder reports menggunakan File Explorer. Tidak ada tombol unduh atau upload internet yang disimulasikan.

Kalimat penjelasan saat uji live: “Tool memakai objek yang diketahui pemiliknya dan kebijakan yang telah diperiksa, kemudian membandingkan pembacaan objek dari dua identitas berbeda. Hasil indikasi tetap harus ditinjau bersama bukti.”

## Dua pembanding dengan HTTP yang sama

- Pilih **Kontrol objek publik** dan muat konfigurasi. Buka Ringkasan lalu jalankan scan. Kedua pengguna menerima HTTP 200 dengan objek sama, tetapi hasilnya **Tidak terindikasi pada kasus ini** karena kebijakan mengizinkan akses.
- Pilih **Kontrol HTTP 200** dan muat konfigurasi. Scan menghasilkan **Tidak terindikasi pada kasus ini** karena respons pengguna B berupa penolakan tanpa objek target, meskipun statusnya HTTP 200.
- Jika password akun B sengaja diubah menjadi nilai yang salah lalu scan dijalankan, hasilnya **Belum dapat disimpulkan**. Kegagalan login tidak membuktikan endpoint aman.

Ketiga konfigurasi hanya mengisi formulir. Pemilihan konfigurasi tidak menjalankan scan dan tidak memaksakan keputusan. Ketika target dimatikan, hasil tidak dapat disimpulkan atau gagal sesuai respons yang diterima.

Kebijakan public pada kontrol lama merupakan kontrak skenario sumber/katalog, bukan pembuktian ACL eksplisit per pembaca. Uji tambahan path sama beserta ACL eksplisit ada di paket tindak lanjut dosen 27 Oktober. Skenario kontrol ini tidak menggantikan paket tersebut atau evaluasi utama.

## Evaluasi opsional

Sebelum scan, buka tab Evaluasi. Untuk lab kendaraan privat saja, label acuan contoh yang sesuai source lab adalah:

    {"Configured dual-token BOLA test": true}

Untuk dua kontrol negatif di atas, nilai labelnya false. Tetapkan label dari source dan bukti independen sebelum scan, bukan dari prediksi tool. Klik kembali ke konfigurasi lalu jalankan. Metrik hasil berasal dari backend. Menyunting label setelah scan tidak menghitung ulang metrik sebelumnya; jalankan pengujian baru. Memuat konfigurasi lab lain mengosongkan label untuk mencegah pemakaian label lama.

Kasus tidak konklusif tetap dipisahkan dari confusion matrix. Skor dari satu eksekusi tidak menjadi hasil penelitian atau ukuran generalisasi.

## API sendiri dan crAPI

Pilih Target kustom, klik Terapkan profil, lalu isi target, akun, mapping objek, JSON path, dan kebijakan yang ditinjau. Konfigurasi sebelumnya tetap berada dalam formulir dan harus diperiksa sebelum diganti ke target lain. Untuk login berbasis username, buka pengaturan autentikasi lanjutan. OpenAPI opsional dapat dipakai menemukan kandidat; ia tidak menetapkan seluruh kebijakan otomatis. Seluruh scan dashboard memakai GET dan timeout 10 detik, termasuk preset kontrol. Ini berbeda dari anggaran 1 detik pada harness kontrol penelitian.

Lab kontrol bawaan tidak memerlukan Docker. crAPI sebenarnya tetap memerlukan Docker, akun/objek pada instance yang benar, serta pemeriksaan ulang pemetaan katalog. Evaluasi utama 40 kasus crAPI dan 16 kontrol tetap terpisah, menunggu tinjauan label dan pembekuan konfigurasi. Dashboard manual bukan pengganti harness evaluasi massal.

## Jika ada kendala

- Engine tidak terhubung: jalankan launcher, lalu muat ulang halaman. Ketika launcher ditutup, server yang dimulainya berhenti.
- Port terpakai: launcher melaporkan konflik. Periksa proses yang memakai port itu; jangan mematikan layanan yang tidak dikenali.
- Halaman masih tampilan lama: gunakan Ctrl+F5. Bila ada server dari checkout lain, pastikan server tersebut dimulai dari folder aplikasi yang dimaksud.
- Gagal login: periksa dua akun target, password, endpoint login, lokasi token, dan pilihan email/username.
- Source atau identitas sesi gagal: periksa respons JSON dan lokasi ID. Jangan mengganti kebijakan supaya mendapatkan indikasi.
- Data formulir dan hasil berada di memori halaman. Reload atau menutup tab menghapusnya; berkas laporan yang telah dibuat tetap tersimpan di folder reports.

Versi ini dipakai untuk uji lokal yang terkontrol. Status siap uji bukan persetujuan administratif sempro atau klaim scanner umum bebas bug.
