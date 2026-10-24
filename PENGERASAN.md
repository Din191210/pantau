# Pantau: audit dan fork pengerasan Purbalingga

Tanggal: 23 Oktober 2026
Basis: `herliansyah/pantau` tag `v0.25.0`, commit `0a5a47af8a492984ad64d73feec46224ba438cce`
Fork: branch `pengerasan-purbalingga` di repo ini, versi `v0.25.0-purbalingga.1`
Status: berjalan sebagai layanan systemd user `pantau.service`, hanya di `127.0.0.1:18090`

## 1. Ringkasan

Pantau layak dipakai sebagai dasbor pemantauan dan alat bantu admin, dengan syarat
ditambal dulu. Kode upstream rapi di banyak tempat (perintah shell konsisten
memakai `shellQuote`, target netdiag divalidasi regex, asal WebSocket dicek), tetapi
ada empat celah yang membuat instalasi bawaan berbahaya bila bisa dijangkau dari jaringan.
Semua sudah ditutup di fork ini dan diuji.

## 2. Temuan

Nomor baris merujuk ke upstream v0.25.0.

| # | Tingkat | Temuan | Bukti | Status |
|---|---|---|---|---|
| T1 | Kritis | Instalasi baru memakai password `admin`, dan selama password itu belum diganti `IsFresh()` bernilai true sehingga `/api/snapshot/import` dan `/api/snapshot/github/restore` menerima permintaan tanpa login. Siapa pun yang lebih dulu menjangkau port bisa mengganti seluruh basis data (hash admin, kunci SSH, daftar host). | `internal/store/db.go:426`, `:1090`; `internal/web/server.go:225`, `:227`, `:2329` | Ditutup |
| T2 | Kritis | Server mendengarkan di semua interface (`:port`), bukan loopback. | `main.go:147` | Ditutup (`-listen`, bawaan 127.0.0.1) |
| T3 | Tinggi | Stored XSS dari nama berkas di server yang dipantau. `escapeHtml` tidak meng-escape `'`, lalu dipakai di `onclick="f('${escapeHtml(x)}')"`. Berkas bernama `a');kode;('.txt` menjalankan `kode` di browser admin saat tombolnya diklik, dan dari sana penyerang memegang terminal root ke semua host. Pesan gagal membuka folder juga menyisipkan path mentah ke `innerHTML`. | `internal/web/static/index.html:10344`, 80 atribut `on*`; `:6271`, `:6282` | Ditutup, terbukti A/B (bagian 4) |
| T4 | Tinggi | Login tanpa batas percobaan; password minimal 4 karakter; sesi 7 hari dan tidak diputus saat password diganti. | `internal/web/server.go:278`, `:613`, `:264` | Ditutup |
| T5 | Sedang | Algoritma SSH lama aktif tanpa diminta (`diffie-hellman-group1-sha1`, `3des-cbc`, `ssh-dss`, `ssh-rsa` SHA-1), membuka jalan serangan downgrade. | `internal/sshrunner/runner.go:138-157` | Ditutup (opt-in `-legacy-ssh`) |
| T6 | Sedang | `ApplyUpdate` mengabaikan `-disable-update-check`; tombol update di UI tetap bisa menimpa binari dengan rilis upstream yang hanya diverifikasi `checksums.txt` dari rilis yang sama (tanpa tanda tangan). | `internal/updater/updater.go:281` | Ditutup; update otomatis mati secara bawaan |
| T7 | Rendah | Tanpa `frame-ancestors` (clickjacking), tanpa `nosniff`. `/api/snapshot/status` membocorkan nama repo backup tanpa login. | `internal/web/server.go:2237`, `:222` | Ditutup |
| T8 | Rendah | Perintah kontainer hanya `docker`; host Podman (Fedora/RHEL, rootless) tidak terbaca. | 5 titik di `inspector.go` dan `server.go` | Ditutup (shim `docker` ke `podman`) |
| T9 | Info | Kunci host SSH diterima otomatis saat koneksi pertama (TOFU). | `internal/sshrunner/runner.go:107`, `:172` | Diterima, lihat bagian 6 |
| T10 | Info | Tombol utama putih di atas `#3b82f6` (kontras 3,7:1); tautan login di bawah 24px. | axe | Ditutup (5,2:1; area sentuh diperbesar) |

## 3. Perubahan di fork

- `main.go`: flag `-listen` (env `PANTAU_LISTEN`, bawaan `127.0.0.1`), `-legacy-ssh`
  (env `PANTAU_LEGACY_SSH`), `-disable-update-check` bawaan `true`, env
  `PANTAU_SECURE_COOKIES=true` untuk cookie `Secure` di belakang TLS. Mencetak lokasi
  berkas password awal.
- `internal/store/db.go`: password admin awal acak (120 bit), ditulis ke
  `<db>.admin-password` mode 0600; berkas DB, WAL, dan SHM di-chmod 0600; folder data 0700.
- `internal/web/server.go`: lockout login 15 menit setelah 5 kali gagal per IP;
  sesi 12 jam, `SameSite=Strict`, sesi kedaluwarsa dibersihkan; ganti password memutus
  semua sesi lain; password minimal 12 karakter; `snapshot/status` wajib login; header
  `frame-ancestors 'none'`, `base-uri 'none'`, `form-action 'self'`, `nosniff`,
  `Referrer-Policy: no-referrer`.
- `internal/sshrunner/runner.go`: profil algoritma modern sebagai bawaan; `ContainerShim`.
- `internal/updater/updater.go`: `ApplyUpdate` menolak bila update dimatikan.
- `internal/web/static/index.html`: helper `jsArg()` (JSON.stringify lalu escape HTML)
  menggantikan 80 interpolasi di atribut `on*`; path gagal dan field host di-escape;
  kontras tombol; tautan restore di layar login dihapus (restore kini lewat Settings
  setelah login).
- Test: test lama yang mengunci perilaku rentan (login `admin`, impor anonim) diubah ke
  perilaku baru; tiga test baru di `pantau_test.go` (`TestHardening_*`).

## 4. Verifikasi yang sudah dijalankan

- `go vet ./...` bersih; `go test ./...` semua paket lulus.
- API langsung (curl ke layanan yang berjalan): anonim `snapshot/status`, `snapshot/import`,
  `hosts` semua 401; login `admin` 401; login dengan password acak 200; percobaan ke-6
  yang salah 429, password benar pun ditolak selama terkunci; `ss` menunjukkan hanya
  `127.0.0.1:18090`.
- Upstream asli (dijalankan terisolasi di namespace jaringan kontainer): anonim
  `snapshot/status` mengembalikan `"fresh":true`, impor anonim lolos autentikasi.
- Uji E2E dengan target sshd sekali pakai: provisioning kunci dengan password sekali
  pakai, inspeksi (status `healthy`, OS terbaca) memakai profil SSH modern, daftar berkas
  lewat SFTP.
- XSS A/B dengan Playwright pada berkas `a');document.title='XSS-OK';('.txt`:
  upstream `xssExecuted: true`, fork `xssExecuted: false` dan editor tetap membuka
  berkas yang benar.
- Shim Podman: dengan PATH yang hanya berisi `podman`, `docker ps` dan `docker inspect`
  dari Pantau membaca kontainer server ini.
- `ui-verify` (375/768/1440, terang dan gelap): tanpa overflow, tanpa temuan axe
  serious/critical. Sisa 3 temuan "moderate" (landmark, h1) adalah struktur upstream.

## 5. Yang belum diaudit mendalam

Dibaca sekilas, belum diuji serangan: kriptografi snapshot (Argon2id + AES-GCM),
implementasi TOTP, terminal WebSocket dan jembatan browser OSC, reverse proxy tunnel
(`/api/tunnel/:host/:port`, bisa ke port mana saja di host target bagi admin yang login),
konkurensi SQLite, transfer antar host. Risiko tunnel dan terminal setara dengan akses
SSH yang memang dimiliki admin, jadi diterima selama dasbor tidak terbuka ke publik.

## 6. Operasi

Akses dari laptop:

    ssh -L 18090:127.0.0.1:18090 server1@<alamat-server>
    # buka http://127.0.0.1:18090

Login pertama: password ada di `~/.local/share/pantau/pantau.db.admin-password`.
Setelah masuk: Settings, ganti password (minimal 12 karakter), aktifkan 2FA, simpan
recovery code, lalu hapus berkas password itu.

Menambah server yang dipantau: Add Host, isi password akun SSH sekali (tidak disimpan),
Pantau memasang kunci publiknya. Pakai akun biasa, bukan root. Untuk server ini sendiri
pakai `server1@127.0.0.1` agar kontainer Podman rootless terlihat. Karena TOFU, lakukan
penambahan host dari jaringan yang dipercaya; sidik jari tersimpan setelah itu.

Server lama (CentOS 5/6): tambahkan `-legacy-ssh` di `ExecStart`, lalu
`systemctl --user daemon-reload && systemctl --user restart pantau`.

Membuka ke LAN: biarkan `-listen 127.0.0.1`, lalu pasang blok di Caddy
yang `reverse_proxy 127.0.0.1:18090` dengan TLS dan pembatasan `remote_ip`, dan set
`Environment=PANTAU_SECURE_COOKIES=true`. Jangan memakai `-listen 0.0.0.0`.

Notifikasi Telegram Pantau: Settings, Notifications. Token yang sama dengan
CVE-Sentinel (`~/.config/cve-sentinel/notify.env`) boleh dipakai.

Lockout login menyimpan status di memori. Bila admin sendiri terkunci:
`systemctl --user restart pantau`.

Membangun ulang setelah mengubah kode:

    cd ~/projects/pantau
    go test ./...
    go build -trimpath -ldflags "-s -w -X main.Version=v0.25.0-purbalingga.N" -o pantau .
    systemctl --user restart pantau

Mengikuti rilis upstream: `git fetch --tags`, rebase branch `pengerasan-purbalingga`,
jalankan ulang test (`TestHardening_*` menjaga tambalan tetap ada).

Rollback: `systemctl --user disable --now pantau`; data ada di `~/.local/share/pantau/`.

## 7. Pusat Keamanan (tambahan fork, v0.25.0-purbalingga.3)

Menyatukan CVE-Sentinel, Wazuh, dan Suricata dalam satu daftar dengan popup otomatis.

- Data: tabel `security_events` (dedup per `dedup_key`, hitungan kejadian, retensi 90 hari).
- Masukan: `POST /api/security/ingest`, hanya dari loopback dan wajib bearer token dari
  `<db>.ingest-token` (0600). Validasi source/category/severity, batas 1 MB dan 500 event.
- Popup: event critical/high yang baru, naik severity, atau serangan/perubahan berkas yang
  muncul lagi setelah ditangani. Lewat SSE ke dasbor, Notification API browser saat tab di
  latar, dan `notify-send` di desktop server (maks 5/menit, isi di-escape). Klik notifikasi
  desktop membuka `http://127.0.0.1:18090/#security-<id>` langsung ke detailnya.
- Dasbor: tombol perisai di header dengan badge; daftar bisa difilter, ditandai ditangani.
- Test: `TestSecurityCenter_IngestDedupPopupAck`; E2E Playwright (popup tanpa reload,
  judul berisi HTML tetap teks, tanpa overflow di 375px, tautan detail).
- Pemasangan Wazuh/Suricata: `~/projects/keamanan-terpadu/`.

## 8. Untuk rencana IISOP

| Kemampuan Pantau | Keputusan | Alasan |
|---|---|---|
| Inspeksi agentless lewat SSH | Adopt | Bekerja, ringan, sudah teruji di sini |
| Desired state dan drift (kontainer, disk, cron) | Adopt | Inti yang berguna; sekarang paham Podman |
| Terminal web, SFTP, editor | Adopt dengan batas | Hanya di loopback/LAN tertutup |
| Tunnel ke port mana saja | Redesign | Perlu daftar port yang diizinkan per host |
| Satu akun admin, sesi di memori | Redesign | Belum ada RBAC dan jejak audit per orang |
| TOFU host key | Redesign | Perlu enrolment sidik jari yang disetujui |
| Self-update dari GitHub | Reject | Tanpa tanda tangan; bangun dari source |
| Snapshot ke GitHub | Extend | Pertimbangkan tujuan backup lokal (disk sdb) |

Kebutuhan yang belum tertutup Pantau dan alat yang sudah ada (CVE-Sentinel, netwatch,
rustwatch, Suricata) sebaiknya didaftar dulu sebelum menulis platform baru.
