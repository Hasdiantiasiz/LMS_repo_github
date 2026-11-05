# Ruang TJKT — LMS SMKN 2 Takalar

Aplikasi pembelajaran untuk administrator, guru, dan siswa. Dibangun dengan PHP 8+ dan SQLite agar bisa dijalankan langsung menggunakan XAMPP tanpa membuat database secara manual.

## Menjalankan aplikasi

1. Letakkan folder ini di `C:\xampp\htdocs\LMS_TJKT`.
2. Jalankan Apache di XAMPP.
3. Buka `http://localhost/LMS_TJKT/`.
4. Database SQLite dan akun awal dibuat otomatis di folder `storage` pada kunjungan pertama.

### Akun awal

| Peran | Username | Kata sandi |
|---|---|---|
| Administrator | `admin` | `admin` |
| Guru | `guru` | `guru` |
| Siswa | `siswa` | `siswa` |

Kata sandi akun awal disimpan dalam bentuk hash. Ganti kata sandi awal setelah masuk dan gunakan kata sandi yang kuat untuk penggunaan di luar lingkungan demo.

## Fitur

- Administrator mengelola akun pengguna dan mata pelajaran, termasuk menetapkan guru pengampu.
- Guru mengunggah materi, membuat tugas dengan batas waktu, mengunduh tugas siswa, memberi nilai 0–100, dan menulis umpan balik.
- Siswa membaca materi, mengunggah atau mengganti pengumpulan tugas, dan melihat nilai serta umpan balik.
- Semua pengguna dapat mengganti kata sandi melalui menu Akun saya.
- Unggahan dibatasi 10 MB dan format PDF, DOC, DOCX, JPG, atau PNG.

Data aplikasi disimpan dalam `storage/lms.sqlite`; berkas tugas disimpan di `storage/uploads`. Jangan menghapus folder `storage` jika ingin mempertahankan data.
