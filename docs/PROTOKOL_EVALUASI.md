# Protokol evaluasi kontribusi BOLA Fuzzer

Protokol ini menambahkan pembandingan aturan keputusan untuk mendukung tujuan Bab I: pembangunan alat, ketepatan deteksi, serta bukti dan biaya pengujian. Status penerimaan kontribusi dan kecukupan baseline masih perlu arahan pembimbing. Perangkat lunak dapat dirilis sebagai aplikasi lokal meskipun persetujuan metodologi dan evaluasi utama belum selesai.

## Kontribusi yang dapat diuji

Kontribusi pengembangan adalah integrasi penemuan kandidat OpenAPI, dua sesi, sumber identitas objek terkonfigurasi, akses silang, analyzer kontekstual, serta pelaporan yang dapat ditelusuri. Kontribusi evaluasi adalah pengukuran keputusan dan kegagalan secara transparan pada cakupan yang ditetapkan.

Hipotesis tambahan: aturan kontekstual dapat mengurangi false positive dibanding aturan lebih sederhana pada observasi HTTP yang sama, dengan tetap melaporkan recall dan cakupan. Hipotesis ini tidak menyatakan bahwa dual-token swapping baru, bahwa kebijakan ditemukan otomatis, atau bahwa alat lebih unggul dari pemindai eksternal. Posisi kebaruan terhadap penelitian terdahulu perlu dibahas bersama Bab II dan pembimbing.

## Metode pembanding yang ditetapkan sebelum eksperimen

| Metode | Informasi keputusan | Ketentuan |
|---|---|---|
| http-status-v1 atau B0 | Status HTTP | Setelah akuisisi objek pemilik dan sesi valid, status sukses dianggap positif; 403/404 negatif; lainnya tidak konklusif. |
| object-identity-v1 atau B1 | Status dan kecocokan identitas objek | Identitas sama dianggap positif; berbeda negatif; identitas tidak tersedia tidak konklusif. Mengabaikan kebijakan dan atribut privat. |
| contextual-v1 atau M | Analyzer produksi | Memakai identitas, kebijakan terkonfigurasi, atribut privat, dan dua sesi terverifikasi. |

Ketiganya memakai prasyarat akuisisi yang sama. Label tidak diberikan kepada fungsi pengambil keputusan. Prediksi dihitung dari bukti HTTP yang sama dan masing-masing menyimpan hash observasinya. Ini membandingkan aturan keputusan setelah akuisisi bersama; tidak membandingkan efektivitas discovery atau kecepatan end-to-end tool berbeda. B0 dan B1 adalah baseline diagnostik yang didefinisikan penelitian ini, bukan replika metode dari paper tertentu.

## Dataset dan pemisahan hasil

1. Dataset kandidat utama yang sudah ada: 40 kasus crAPI dari sepuluh pasangan akun dan 16 kasus kontrol. Peninjauan label dan pembekuan final tetap diperlukan. Kasus berbagi dua template crAPI; kelas juga dipengaruhi jenis endpoint.
2. Dataset pembanding mekanisme: delapan kondisi pada template netral yang sama `/objects/{id}`, masing-masing dua arah sehingga 16 kasus. Meliputi kebocoran privat, penolakan 403, akses publik, berbagi sah, error HTTP 200, objek lain, simulasi 401, dan kebocoran tertunda.
3. Dataset mekanisme merupakan kontrol yang telah dipakai selama pengembangan. Ini bukan holdout independen pada endpoint baru. Hasilnya dipisahkan dari 40+16 kasus utama.

Jangan menjumlahkan pengulangan, arah berlawanan, atau penggunaan ulang template sebagai sampel API independen. Perbandingan pada path sama membantu mengurangi pengaruh nama endpoint dalam pemeriksaan mekanisme, tetapi tidak membuktikan generalisasi.

## Ground truth dan tinjauan manusia

Perintah prepare menyimpan kebijakan/ACL fixture, kepemilikan, rencana kasus, dan label kandidat; memeriksa pembacaan pemilik dan akses silang dengan HTTP langsung beranggaran lebih panjang; kemudian membekukan manifest sebelum scanner produksi diimpor. Bukti ini memberi pemisahan prosedural dari prediksi scanner. Pemeriksaan terprogram dengan bantuan AI tidak menggantikan penilai manusia independen.

Reviewer memeriksa setiap kasus berdasarkan pemilik, izin, implementasi, serta bukti HTTP. Berkas `review.json` memuat identitas reviewer, tanggal, hash manifest yang ditinjau, persetujuan tiap kasus, dan dasar penilaiannya. Setelah semua benar, reviewer dapat mengisi status `approved`, `accepted: true`, dan catatan basis. Koreksi label atau fixture memerlukan kandidat dan manifest baru, kemudian tinjauan ulang. Hash hanya menjamin integritas, bukan kebenaran semantik label.

Mode `main` menolak review yang belum lengkap atau tidak cocok dengan manifest. Rekaman tersebut merupakan dokumentasi review manual, bukan autentikasi identitas reviewer. Persetujuan pembimbing atas protokol tetap diperoleh di luar aplikasi. Jangan mengisi persetujuan atas nama dosen.

## Menjalankan pembandingan mekanisme

Prasyarat: Python 3.10 atau lebih baru. Fixture berjalan di loopback pada port sementara dan berhenti setelah eksperimen. Tidak memerlukan Docker atau dependensi tambahan.

```text
python compare_methods.py prepare --out experiments/mechanism-candidate
python compare_methods.py run --dataset experiments/mechanism-candidate --out experiments/comparison-pilot --repetitions 3 --purpose pilot
```

Gunakan direktori baru untuk setiap prepare atau run. Setelah protokol diterima dan review manusia lengkap:

```text
python compare_methods.py run --dataset experiments/mechanism-candidate --out experiments/comparison-reviewed --repetitions 3 --purpose main
```

Untuk dataset utama yang disiapkan terpisah, `experiment.py control` atau `experiment.py crapi` sekarang juga menyimpan hasil B0, B1, dan M dari observasi yang sama dalam `run-N/comparison/`. Mode baku adalah `pilot`. Mode `--purpose main --review <review.json>` memerlukan review seluruh kasus dengan hash `ground-truth-manifest.json` yang cocok. File akun dan dataset privat tidak dikemas dalam repo; `experiment.py crapi` memerlukan penyiapan dataset tersebut terlebih dahulu.

## Metrik dan analisis

- Laporkan TP, FP, TN, FN, precision, recall konklusif, F1, dan false positive rate bila penyebutnya tersedia.
- Laporkan jumlah direncanakan, konklusif, tidak konklusif, dan cakupan. Kegagalan tidak dipetakan menjadi negatif.
- Recall operasional adalah TP dibagi seluruh kasus berlabel positif, termasuk positif yang tidak selesai. Recall konklusif hanya menggunakan kasus yang mendapat keputusan konklusif.
- Bandingkan keputusan per case_id. Laporkan pasangan salah menjadi benar, benar menjadi salah, dan perubahan dari/ke tidak konklusif secara terpisah.
- Sajikan hasil setiap run dan konsistensinya. Jangan melaporkan signifikansi populasi dari sedikit cluster skenario dan dua template yang berulang.
- Biaya HTTP dan waktu akuisisi dilaporkan sekali karena observasinya dipakai bersama. Tidak ditafsirkan sebagai perbedaan kecepatan antar-metode.

Uji mekanisme memakai timeout pemindai 3 detik, delay fixture 4 detik, dan HTTP independen 8 detik. Kontrol utama memakai anggaran berbeda (1 detik dan delay 3 detik). Dashboard manual memakai 10 detik. Durasi antarprotokol ini tidak digabung tanpa penjelasan.

## Artefak reproduksi

Simpan manifest dataset, snapshot review, versi Python, hash source dan harness, protokol, fixture, bukti HTTP, prediksi setiap metode, metrik tiap run, ringkasan pasangan, serta waktu dan jumlah permintaan. Token dan password tidak dicantumkan dalam rekaman scan. Untuk mengulang endpoint nyata, autentikasi ulang dengan akun uji dan pemetaan objek yang masih valid.

Jika mengubah aturan berdasarkan hasil pilot, perlakukan perubahan sebagai pengembangan. Tetapkan ulang versi sebelum evaluasi yang ditujukan untuk pembuktian. Pemilihan tool pembanding eksternal, penambahan endpoint holdout, dan ablation setiap komponen secara terpisah merupakan perluasan protokol yang perlu disepakati sebelum klaim diperluas.
