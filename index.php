<?php
declare(strict_types=1);
require __DIR__ . DIRECTORY_SEPARATOR . 'bootstrap.php';

$page = (string) ($_GET['page'] ?? 'dashboard');
$user = current_user();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = (string) ($_POST['action'] ?? '');
    $redirectPage = (string) ($_POST['return_page'] ?? 'dashboard');
    try {
        verify_csrf();

        if ($action === 'login') {
            $username = trim((string) ($_POST['username'] ?? ''));
            $password = (string) ($_POST['password'] ?? '');
            $statement = $db->prepare('SELECT id, username, name, role, password_hash FROM users WHERE username = ?');
            $statement->execute([$username]);
            $account = $statement->fetch();
            if (!$account || !password_verify($password, $account['password_hash'])) {
                throw new RuntimeException('Username atau password tidak sesuai.');
            }
            session_regenerate_id(true);
            unset($account['password_hash']);
            $_SESSION['user'] = $account;
            flash('Selamat datang, ' . $account['name'] . '!');
            go('dashboard');
        }

        if ($action === 'logout') {
            $_SESSION = [];
            session_destroy();
            header('Location: index.php');
            exit;
        }

        $user = require_login();

        if ($action === 'change_password') {
            $account = require_login();
            $currentPassword = (string) ($_POST['current_password'] ?? '');
            $newPassword = (string) ($_POST['new_password'] ?? '');
            $confirmPassword = (string) ($_POST['confirm_password'] ?? '');
            $statement = $db->prepare('SELECT password_hash FROM users WHERE id = ?');
            $statement->execute([$account['id']]);
            $passwordHash = $statement->fetchColumn();
            if (!$passwordHash || !password_verify($currentPassword, $passwordHash)) {
                throw new RuntimeException('Kata sandi saat ini tidak sesuai.');
            }
            if (strlen($newPassword) < 8) {
                throw new RuntimeException('Kata sandi baru harus terdiri dari minimal 8 karakter.');
            }
            if ($newPassword !== $confirmPassword) {
                throw new RuntimeException('Konfirmasi kata sandi baru tidak cocok.');
            }
            $statement = $db->prepare('UPDATE users SET password_hash = ? WHERE id = ?');
            $statement->execute([password_hash($newPassword, PASSWORD_DEFAULT), $account['id']]);
            flash('Kata sandi berhasil diperbarui.');
            go('account');
        }

        if ($action === 'create_user') {
            require_role(['admin']);
            $username = trim((string) ($_POST['username'] ?? ''));
            $name = trim((string) ($_POST['name'] ?? ''));
            $password = (string) ($_POST['password'] ?? '');
            $role = (string) ($_POST['role'] ?? '');
            if ($username === '' || $name === '' || strlen($password) < 6 || !in_array($role, ['admin', 'guru', 'siswa'], true)) {
                throw new RuntimeException('Lengkapi nama, username, peran, dan kata sandi minimal 6 karakter.');
            }
            $statement = $db->prepare('INSERT INTO users (username, name, role, password_hash) VALUES (?, ?, ?, ?)');
            $statement->execute([$username, $name, $role, password_hash($password, PASSWORD_DEFAULT)]);
            flash('Akun berhasil ditambahkan.');
            go('users');
        }

        if ($action === 'delete_user') {
            $admin = require_role(['admin']);
            $id = (int) ($_POST['id'] ?? 0);
            if ($id === (int) $admin['id']) {
                throw new RuntimeException('Akun yang sedang digunakan tidak dapat dihapus.');
            }
            $statement = $db->prepare('DELETE FROM users WHERE id = ?');
            $statement->execute([$id]);
            flash('Akun berhasil dihapus.');
            go('users');
        }

        if ($action === 'create_subject') {
            require_role(['admin']);
            $name = trim((string) ($_POST['name'] ?? ''));
            $code = strtoupper(trim((string) ($_POST['code'] ?? '')));
            $teacherId = (int) ($_POST['teacher_id'] ?? 0);
            if ($name === '' || $code === '') {
                throw new RuntimeException('Nama dan kode mata pelajaran wajib diisi.');
            }
            $statement = $db->prepare("INSERT INTO subjects (name, code, teacher_id) VALUES (?, ?, NULLIF(?, 0))");
            $statement->execute([$name, $code, $teacherId]);
            flash('Mata pelajaran berhasil ditambahkan.');
            go('subjects');
        }

        if ($action === 'delete_subject') {
            require_role(['admin']);
            $statement = $db->prepare('DELETE FROM subjects WHERE id = ?');
            $statement->execute([(int) ($_POST['id'] ?? 0)]);
            flash('Mata pelajaran dan konten terkait berhasil dihapus.');
            go('subjects');
        }

        if ($action === 'create_material') {
            $actor = require_role(['admin', 'guru']);
            $subjectId = (int) ($_POST['subject_id'] ?? 0);
            $title = trim((string) ($_POST['title'] ?? ''));
            $content = trim((string) ($_POST['content'] ?? ''));
            $link = trim((string) ($_POST['link'] ?? ''));
            if (!can_access_subject($db, $actor, $subjectId)) {
                throw new RuntimeException('Mata pelajaran tersebut bukan tanggung jawab Anda.');
            }
            if ($title === '' || $content === '') {
                throw new RuntimeException('Judul dan isi materi wajib diisi.');
            }
            if ($link !== '' && (!filter_var($link, FILTER_VALIDATE_URL) || !in_array(parse_url($link, PHP_URL_SCHEME), ['http', 'https'], true))) {
                throw new RuntimeException('Tautan materi harus berupa URL HTTP atau HTTPS yang valid.');
            }
            $statement = $db->prepare('INSERT INTO materials (subject_id, user_id, title, content, link) VALUES (?, ?, ?, ?, ?)');
            $statement->execute([$subjectId, $actor['id'], $title, $content, $link ?: null]);
            flash('Materi berhasil dipublikasikan.');
            go('materials');
        }

        if ($action === 'create_assignment') {
            $actor = require_role(['admin', 'guru']);
            $subjectId = (int) ($_POST['subject_id'] ?? 0);
            $title = trim((string) ($_POST['title'] ?? ''));
            $description = trim((string) ($_POST['description'] ?? ''));
            $dueDate = trim((string) ($_POST['due_date'] ?? ''));
            if (!can_access_subject($db, $actor, $subjectId)) {
                throw new RuntimeException('Mata pelajaran tersebut bukan tanggung jawab Anda.');
            }
            if ($title === '' || $description === '') {
                throw new RuntimeException('Judul dan petunjuk tugas wajib diisi.');
            }
            if ($dueDate !== '' && !DateTime::createFromFormat('Y-m-d\TH:i', $dueDate)) {
                throw new RuntimeException('Batas waktu tugas tidak valid.');
            }
            $dueDate = $dueDate === '' ? null : str_replace('T', ' ', $dueDate) . ':00';
            $statement = $db->prepare('INSERT INTO assignments (subject_id, user_id, title, description, due_date) VALUES (?, ?, ?, ?, ?)');
            $statement->execute([$subjectId, $actor['id'], $title, $description, $dueDate]);
            flash('Tugas berhasil dipublikasikan.');
            go('tasks');
        }

        if ($action === 'submit_assignment') {
            $student = require_role(['siswa']);
            $assignmentId = (int) ($_POST['assignment_id'] ?? 0);
            $assignment = $db->prepare('SELECT id FROM assignments WHERE id = ?');
            $assignment->execute([$assignmentId]);
            if (!$assignment->fetch()) {
                throw new RuntimeException('Tugas tidak ditemukan.');
            }
            if (!isset($_FILES['submission']) || $_FILES['submission']['error'] !== UPLOAD_ERR_OK) {
                throw new RuntimeException('Pilih berkas tugas yang valid untuk diunggah.');
            }
            $file = $_FILES['submission'];
            if ($file['size'] > MAX_UPLOAD_BYTES) {
                throw new RuntimeException('Ukuran berkas maksimal 10 MB.');
            }
            $originalName = basename((string) $file['name']);
            $extension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
            $allowed = [
                'pdf' => ['application/pdf'],
                'doc' => ['application/msword', 'application/octet-stream'],
                'docx' => ['application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/zip', 'application/octet-stream'],
                'jpg' => ['image/jpeg'],
                'jpeg' => ['image/jpeg'],
                'png' => ['image/png'],
            ];
            $mime = (new finfo(FILEINFO_MIME_TYPE))->file($file['tmp_name']);
            if (!isset($allowed[$extension]) || !in_array($mime, $allowed[$extension], true)) {
                throw new RuntimeException('Format berkas harus PDF, DOC, DOCX, JPG, JPEG, atau PNG.');
            }
            $uploadDir = __DIR__ . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'uploads';
            if (!is_dir($uploadDir) && !mkdir($uploadDir, 0775, true) && !is_dir($uploadDir)) {
                throw new RuntimeException('Folder unggahan tidak dapat dibuat.');
            }
            $storedName = bin2hex(random_bytes(20)) . '.' . $extension;
            if (!move_uploaded_file($file['tmp_name'], $uploadDir . DIRECTORY_SEPARATOR . $storedName)) {
                throw new RuntimeException('Berkas gagal disimpan. Periksa izin folder storage.');
            }
            $statement = $db->prepare(
                'INSERT INTO submissions (assignment_id, student_id, file_name, stored_name) VALUES (?, ?, ?, ?)
                 ON CONFLICT(assignment_id, student_id) DO UPDATE SET file_name = excluded.file_name,
                 stored_name = excluded.stored_name, submitted_at = CURRENT_TIMESTAMP'
            );
            $statement->execute([$assignmentId, $student['id'], $originalName, $storedName]);
            flash('Tugas berhasil diunggah. Anda dapat mengunggah ulang sebelum batas waktu.');
            go('tasks');
        }

        if ($action === 'grade_submission') {
            $teacher = require_role(['admin', 'guru']);
            $submissionId = (int) ($_POST['submission_id'] ?? 0);
            $score = filter_var($_POST['score'] ?? null, FILTER_VALIDATE_FLOAT);
            $feedback = trim((string) ($_POST['feedback'] ?? ''));
            $submissionQuery = $db->prepare(
                'SELECT a.subject_id FROM submissions s JOIN assignments a ON a.id = s.assignment_id WHERE s.id = ?'
            );
            $submissionQuery->execute([$submissionId]);
            $submission = $submissionQuery->fetch();
            if (!$submission || !can_access_subject($db, $teacher, (int) $submission['subject_id'])) {
                throw new RuntimeException('Pengumpulan tugas tidak ditemukan atau bukan tanggung jawab Anda.');
            }
            if ($score === false || $score < 0 || $score > 100) {
                throw new RuntimeException('Nilai harus berupa angka antara 0 sampai 100.');
            }
            $statement = $db->prepare(
                'INSERT INTO grades (submission_id, teacher_id, score, feedback) VALUES (?, ?, ?, ?)
                 ON CONFLICT(submission_id) DO UPDATE SET teacher_id = excluded.teacher_id,
                 score = excluded.score, feedback = excluded.feedback, graded_at = CURRENT_TIMESTAMP'
            );
            $statement->execute([$submissionId, $teacher['id'], $score, $feedback]);
            flash('Nilai dan umpan balik berhasil disimpan.');
            go('tasks');
        }

        throw new RuntimeException('Tindakan tidak dikenali.');
    } catch (Throwable $exception) {
        flash($exception->getMessage(), 'error');
        go($redirectPage);
    }
}

$user = current_user();
$flashMessage = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);

if (!$user):
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Masuk · <?= h(APP_NAME) ?></title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body class="login-page">
<main class="login-shell">
    <section class="login-intro">
        <div class="brand-mark">T</div>
        <p class="eyebrow">SMKN 2 TAKALAR</p>
        <p class="login-program">PROGRAM KEAHLIAN TJKT</p>
        <h1>Belajar, berkarya,<br>dan terhubung.</h1>
        <p class="muted">Satu ruang untuk materi, tugas, dan perkembangan belajar TJKT.</p>
        <img class="login-network-art" src="assets/tkj-network.svg" alt="" aria-hidden="true">
    </section>
    <section class="login-card">
        <div class="login-school"><img src="assets/tkj-network.svg" alt="" aria-hidden="true"><span><strong>SMKN 2 Takalar</strong><small>Program Keahlian TJKT</small></span></div>
        <div class="mobile-brand"><span class="brand-mark">T</span><span>Ruang TJKT</span></div>
        <p class="eyebrow">SELAMAT DATANG KEMBALI</p>
        <h2>Masuk ke akun</h2>
        <p class="muted">Gunakan username dan kata sandi yang diberikan.</p>
        <?php if ($flashMessage): ?><div class="alert <?= h($flashMessage['type']) ?>"><?= h($flashMessage['message']) ?></div><?php endif; ?>
        <form method="post" class="stack-form">
            <input type="hidden" name="csrf_token" value="<?= h(csrf_token()) ?>">
            <input type="hidden" name="action" value="login">
            <label>Username<input name="username" autocomplete="username" required autofocus placeholder="Masukkan username"></label>
            <label>Kata sandi<input type="password" name="password" autocomplete="current-password" required placeholder="Masukkan kata sandi"></label>
            <button class="button primary wide" type="submit">Masuk ke LMS <span>→</span></button>
        </form>
        <div class="demo-accounts">
            <strong>Akun awal</strong>
            <span>admin / admin</span><span>guru / guru</span><span>siswa / siswa</span>
        </div>
    </section>
</main>
</body>
</html>
<?php
exit;
endif;

$roleNames = ['admin' => 'Administrator', 'guru' => 'Guru', 'siswa' => 'Siswa'];
$navItems = [
    'dashboard' => ['Ikhtisar', '⌂'],
    'materials' => ['Materi belajar', '▤'],
    'tasks' => ['Tugas', '▣'],
    'grades' => ['Nilai', '▥'],
    'account' => ['Akun saya', '⚙'],
];
if ($user['role'] === 'admin') {
    $navItems['subjects'] = ['Mata pelajaran', '▧'];
    $navItems['users'] = ['Pengguna', '♙'];
}
$page = array_key_exists($page, $navItems) ? $page : 'dashboard';

$subjectSql = 'SELECT s.*, u.name AS teacher_name FROM subjects s LEFT JOIN users u ON u.id = s.teacher_id';
if ($user['role'] === 'guru') {
    $subjectQuery = $db->prepare($subjectSql . ' WHERE s.teacher_id = ? ORDER BY s.name');
    $subjectQuery->execute([$user['id']]);
    $subjects = $subjectQuery->fetchAll();
} else {
    $subjects = $db->query($subjectSql . ' ORDER BY s.name')->fetchAll();
}
$subjectById = [];
foreach ($subjects as $subject) {
    $subjectById[$subject['id']] = $subject;
}

$contentQuery = static function (string $sql, array $params = []) use ($db): array {
    $statement = $db->prepare($sql);
    $statement->execute($params);
    return $statement->fetchAll();
};

$materialsSql = 'SELECT m.*, s.name AS subject_name, u.name AS author_name FROM materials m JOIN subjects s ON s.id = m.subject_id LEFT JOIN users u ON u.id = m.user_id';
$assignmentsSql = 'SELECT a.*, s.name AS subject_name, u.name AS author_name FROM assignments a JOIN subjects s ON s.id = a.subject_id LEFT JOIN users u ON u.id = a.user_id';
$scopeSql = '';
$scopeParams = [];
if ($user['role'] === 'guru') {
    $scopeSql = ' WHERE s.teacher_id = ?';
    $scopeParams[] = $user['id'];
}
$materials = $contentQuery($materialsSql . $scopeSql . ' ORDER BY m.created_at DESC', $scopeParams);
$assignments = $contentQuery($assignmentsSql . $scopeSql . ' ORDER BY CASE WHEN a.due_date IS NULL THEN 1 ELSE 0 END, a.due_date ASC, a.created_at DESC', $scopeParams);

$studentSubmissions = [];
if ($user['role'] === 'siswa') {
    $statement = $db->prepare('SELECT * FROM submissions WHERE student_id = ?');
    $statement->execute([$user['id']]);
    foreach ($statement->fetchAll() as $row) {
        $studentSubmissions[$row['assignment_id']] = $row;
    }
}

$submissions = [];
if (in_array($user['role'], ['admin', 'guru'], true)) {
    $submissionSql = 'SELECT s.*, u.name AS student_name, u.username, a.title AS assignment_title, a.subject_id,
                      g.score, g.feedback, g.graded_at, sub.name AS subject_name
                      FROM submissions s JOIN users u ON u.id = s.student_id
                      JOIN assignments a ON a.id = s.assignment_id
                      JOIN subjects sub ON sub.id = a.subject_id
                      LEFT JOIN grades g ON g.submission_id = s.id';
    if ($user['role'] === 'guru') {
        $statement = $db->prepare($submissionSql . ' WHERE sub.teacher_id = ? ORDER BY s.submitted_at DESC');
        $statement->execute([$user['id']]);
        $submissions = $statement->fetchAll();
    } else {
        $submissions = $db->query($submissionSql . ' ORDER BY s.submitted_at DESC')->fetchAll();
    }
}

$grades = [];
if ($user['role'] === 'siswa') {
    $statement = $db->prepare(
        'SELECT g.*, a.title AS assignment_title, sub.name AS subject_name, u.name AS teacher_name
         FROM grades g JOIN submissions s ON s.id = g.submission_id
         JOIN assignments a ON a.id = s.assignment_id JOIN subjects sub ON sub.id = a.subject_id
         LEFT JOIN users u ON u.id = g.teacher_id WHERE s.student_id = ? ORDER BY g.graded_at DESC'
    );
    $statement->execute([$user['id']]);
    $grades = $statement->fetchAll();
} elseif ($user['role'] === 'guru') {
    $grades = $contentQuery(
        'SELECT g.*, a.title AS assignment_title, sub.name AS subject_name, u.name AS student_name
         FROM grades g JOIN submissions s ON s.id = g.submission_id
         JOIN assignments a ON a.id = s.assignment_id JOIN subjects sub ON sub.id = a.subject_id
         JOIN users u ON u.id = s.student_id WHERE sub.teacher_id = ? ORDER BY g.graded_at DESC',
        [$user['id']]
    );
} else {
    $grades = $contentQuery(
        'SELECT g.*, a.title AS assignment_title, sub.name AS subject_name, u.name AS student_name
         FROM grades g JOIN submissions s ON s.id = g.submission_id
         JOIN assignments a ON a.id = s.assignment_id JOIN subjects sub ON sub.id = a.subject_id
         JOIN users u ON u.id = s.student_id ORDER BY g.graded_at DESC'
    );
}

$userCounts = ['admin' => 0, 'guru' => 0, 'siswa' => 0];
if ($user['role'] === 'admin') {
    foreach ($db->query('SELECT role, COUNT(*) AS total FROM users GROUP BY role') as $row) {
        $userCounts[$row['role']] = (int) $row['total'];
    }
}

$visibleSubmissions = count($submissions);
$pendingCount = count(array_filter($submissions, static fn (array $row): bool => $row['score'] === null));
$mySubmittedCount = count($studentSubmissions);
$studentTaskProgress = count($assignments) > 0
    ? (int) round(($mySubmittedCount / count($assignments)) * 100)
    : 0;
$studentAverageScore = count($grades) > 0
    ? (int) round(array_sum(array_map(static fn (array $grade): float => (float) $grade['score'], $grades)) / count($grades))
    : null;
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= h($navItems[$page][0]) ?> · <?= h(APP_NAME) ?></title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body class="app-page">
<div class="app-layout">
    <aside class="sidebar">
        <a class="brand" href="index.php"><span class="brand-mark">T</span><span>Ruang TJKT<small>SMKN 2 Takalar</small></span></a>
        <div class="side-label">MENU UTAMA</div>
        <nav class="side-nav">
            <?php foreach ($navItems as $key => [$label, $icon]): ?>
                <a class="<?= $page === $key ? 'active' : '' ?>" href="?page=<?= h($key) ?>"><span class="nav-icon"><?= h($icon) ?></span><?= h($label) ?><?php if ($key === 'tasks' && $user['role'] === 'guru' && $pendingCount): ?><span class="nav-badge"><?= $pendingCount ?></span><?php endif; ?></a>
            <?php endforeach; ?>
        </nav>
        <div class="sidebar-bottom">
            <div class="mini-profile"><div class="avatar"><?= h(strtoupper(substr($user['name'], 0, 1))) ?></div><div><strong><?= h($user['name']) ?></strong><small><?= h($roleNames[$user['role']]) ?></small></div></div>
            <form method="post">
                <input type="hidden" name="csrf_token" value="<?= h(csrf_token()) ?>">
                <input type="hidden" name="action" value="logout">
                <button class="logout-button" type="submit"><span>↪</span> Keluar</button>
            </form>
        </div>
    </aside>
    <main class="main-content">
        <header class="topbar"><div><span class="topbar-school">SMKN 2 TAKALAR</span><h1><?= h($navItems[$page][0]) ?></h1></div><div class="topbar-right"><span class="today"><?= h(date('l, d F Y')) ?></span><a class="topbar-profile" href="?page=account" aria-label="Buka akun <?= h($user['name']) ?>"><span class="topbar-user-copy"><strong><?= h($user['name']) ?></strong><small><?= h($roleNames[$user['role']]) ?></small></span><span class="avatar"><?= h(strtoupper(substr($user['name'], 0, 1))) ?></span></a></div></header>
        <div class="content-wrap">
            <?php if ($flashMessage): ?><div class="alert <?= h($flashMessage['type']) ?>"><?= h($flashMessage['message']) ?></div><?php endif; ?>

            <?php if ($page === 'dashboard'): ?>
                <section class="welcome-banner">
                    <div class="welcome-copy">
                        <p class="eyebrow"><?= $user['role'] === 'siswa' ? 'HARI INI ADALAH KESEMPATAN BARU' : 'RUANG BELAJAR TJKT' ?></p>
                        <h2>Halo, <?= h(explode(' ', $user['name'])[0]) ?> 👋</h2>
                        <p><?= $user['role'] === 'siswa' ? 'Setiap langkah kecil membawamu lebih dekat ke cita-cita. Yuk, lanjut belajar!' : ($user['role'] === 'guru' ? 'Kelola materi, tugas, dan pantau perkembangan siswa.' : 'Ringkasan aktivitas pembelajaran dan pengelolaan LMS.') ?></p>
                        <?php if ($user['role'] === 'siswa'): ?>
                            <div class="student-quick-links"><a href="?page=tasks">Lihat tugas <span>→</span></a><a href="?page=materials">Buka materi <span>→</span></a></div>
                        <?php endif; ?>
                    </div>
                    <div class="banner-art" aria-hidden="true"><img src="assets/tkj-network.svg" alt=""><span class="banner-art-label">JARINGAN · KOMPUTER · TEKNOLOGI</span></div>
                </section>
                <?php if ($user['role'] === 'siswa'): ?>
                    <section class="student-motivation">
                        <div class="student-progress-copy"><span class="progress-icon" aria-hidden="true">✦</span><div><p class="eyebrow">LANGKAH BELAJARMU</p><h3><?= count($assignments) > 0 ? ($studentTaskProgress === 100 ? 'Hebat! Semua tugas sudah dikumpulkan.' : 'Terus melangkah, kamu pasti bisa!') : 'Perjalanan belajarmu dimulai di sini.' ?></h3><p><?= count($assignments) > 0 ? h($mySubmittedCount) . ' dari ' . h(count($assignments)) . ' tugas sudah kamu kumpulkan.' : 'Materi dan tugas baru dari guru akan muncul di sini.' ?></p></div></div>
                        <div class="progress-visual"><div class="progress-track" role="progressbar" aria-label="Progres pengumpulan tugas" aria-valuenow="<?= h($studentTaskProgress) ?>" aria-valuemin="0" aria-valuemax="100"><span style="width: <?= h($studentTaskProgress) ?>%"></span></div><strong><?= h($studentTaskProgress) ?>%</strong></div>
                        <div class="student-achievement"><span class="achievement-icon" aria-hidden="true"><?= $studentAverageScore !== null && $studentAverageScore >= 85 ? '★' : '✧' ?></span><div><small>SEMANGAT BELAJAR</small><strong><?= $studentAverageScore !== null ? 'Rata-rata nilai ' . h($studentAverageScore) : 'Satu tugas, satu kemajuan' ?></strong></div></div>
                    </section>
                <?php endif; ?>
                <section class="stats-grid">
                    <?php if ($user['role'] === 'admin'): ?>
                        <article class="stat-card"><span class="stat-icon violet">♙</span><span class="stat-label">Total pengguna</span><strong><?= array_sum($userCounts) ?></strong><small><?= $userCounts['guru'] ?> guru · <?= $userCounts['siswa'] ?> siswa</small></article>
                        <article class="stat-card"><span class="stat-icon blue">▧</span><span class="stat-label">Mata pelajaran</span><strong><?= count($subjects) ?></strong><small>Program keahlian TJKT</small></article>
                        <article class="stat-card"><span class="stat-icon orange">▣</span><span class="stat-label">Pengumpulan tugas</span><strong><?= $visibleSubmissions ?></strong><small><?= $pendingCount ?> perlu dinilai</small></article>
                    <?php elseif ($user['role'] === 'guru'): ?>
                        <article class="stat-card"><span class="stat-icon violet">▧</span><span class="stat-label">Mata pelajaran</span><strong><?= count($subjects) ?></strong><small>Diampu oleh Anda</small></article>
                        <article class="stat-card"><span class="stat-icon orange">▣</span><span class="stat-label">Perlu dinilai</span><strong><?= $pendingCount ?></strong><small>Dari <?= $visibleSubmissions ?> pengumpulan</small></article>
                        <article class="stat-card"><span class="stat-icon blue">▤</span><span class="stat-label">Materi & tugas</span><strong><?= count($materials) + count($assignments) ?></strong><small>Konten pembelajaran</small></article>
                    <?php else: ?>
                        <article class="stat-card"><span class="stat-icon violet">▤</span><span class="stat-label">Materi belajar</span><strong><?= count($materials) ?></strong><small>Siap dipelajari</small></article>
                        <article class="stat-card"><span class="stat-icon orange">▣</span><span class="stat-label">Tugas aktif</span><strong><?= count($assignments) ?></strong><small><?= $mySubmittedCount ?> sudah dikumpulkan</small></article>
                        <article class="stat-card"><span class="stat-icon green">▥</span><span class="stat-label">Nilai diterima</span><strong><?= count($grades) ?></strong><small>Dari guru mata pelajaran</small></article>
                    <?php endif; ?>
                </section>
                <section class="section-grid">
                    <div class="panel"><div class="panel-heading"><div><p class="eyebrow">TERBARU</p><h3>Tugas mendatang</h3></div><a class="text-link" href="?page=tasks">Lihat semua →</a></div>
                        <?php if (!$assignments): ?><div class="empty-state"><span>▣</span><strong>Belum ada tugas</strong><p>Tugas yang dibuat akan muncul di sini.</p></div><?php else: ?>
                            <div class="compact-list"><?php foreach (array_slice($assignments, 0, 4) as $assignment): ?><a href="?page=tasks" class="compact-item"><span class="list-icon">▣</span><span class="compact-main"><strong><?= h($assignment['title']) ?></strong><small><?= h($assignment['subject_name']) ?> · <?= h($assignment['author_name'] ?? 'Pengajar') ?></small></span><span class="compact-date"><?= $assignment['due_date'] ? h(date('d M', strtotime($assignment['due_date']))) : '—' ?></span></a><?php endforeach; ?></div>
                        <?php endif; ?>
                    </div>
                    <div class="panel highlight-panel"><p class="eyebrow">RUANG TJKT</p><h3>Belajar selangkah lebih terarah.</h3><p>Temukan materi, kumpulkan tugas, dan pantau hasil belajarmu di satu tempat.</p><div class="highlight-foot"><span>SMKN 2 Takalar</span><span>● Aktif</span></div></div>
                </section>

            <?php elseif ($page === 'materials'): ?>
                <?php if (in_array($user['role'], ['admin', 'guru'], true)): ?>
                    <section class="panel form-panel"><div class="panel-heading"><div><p class="eyebrow">BAGIKAN PENGETAHUAN</p><h3>Tambah materi belajar</h3></div></div>
                        <?php if (!$subjects): ?><p class="muted">Belum ada mata pelajaran yang ditugaskan kepada Anda. Hubungi administrator.</p><?php else: ?>
                            <form method="post" class="form-grid">
                                <?= csrf_input() ?><input type="hidden" name="action" value="create_material"><input type="hidden" name="return_page" value="materials">
                                <label>Mata pelajaran<select name="subject_id" required><?php foreach ($subjects as $subject): ?><option value="<?= h($subject['id']) ?>"><?= h($subject['code'] . ' · ' . $subject['name']) ?></option><?php endforeach; ?></select></label>
                                <label>Judul materi<input name="title" required maxlength="160" placeholder="Contoh: Pengenalan Jaringan Komputer"></label>
                                <label class="full-span">Isi / ringkasan materi<textarea name="content" rows="3" required placeholder="Tuliskan penjelasan atau arahan belajar..."></textarea></label>
                                <label class="full-span">Tautan tambahan <span class="optional">(opsional)</span><input type="url" name="link" placeholder="https://..."></label>
                                <div class="full-span form-actions"><button class="button primary" type="submit">Publikasikan materi</button></div>
                            </form>
                        <?php endif; ?>
                    </section>
                <?php endif; ?>
                <div class="section-title"><div><p class="eyebrow">PERPUSTAKAAN KELAS</p><h2>Materi belajar</h2></div><span class="count-pill"><?= count($materials) ?> materi</span></div>
                <?php if (!$materials): ?><div class="panel empty-state"><span>▤</span><strong>Belum ada materi</strong><p>Materi yang dibagikan guru akan tampil di sini.</p></div><?php else: ?>
                    <div class="card-grid"><?php foreach ($materials as $material): ?><article class="content-card"><div class="card-topline"><span class="subject-tag"><?= h($material['subject_name']) ?></span><span class="card-date"><?= h(date('d M Y', strtotime($material['created_at']))) ?></span></div><h3><?= h($material['title']) ?></h3><p class="card-copy"><?= nl2br(h($material['content'])) ?></p><?php if ($material['link']): ?><a class="button secondary small" href="<?= h($material['link']) ?>" target="_blank" rel="noopener noreferrer">Buka materi ↗</a><?php endif; ?><div class="card-author">Dibagikan oleh <?= h($material['author_name'] ?? 'Pengajar') ?></div></article><?php endforeach; ?></div>
                <?php endif; ?>

            <?php elseif ($page === 'tasks'): ?>
                <?php if (in_array($user['role'], ['admin', 'guru'], true)): ?>
                    <section class="panel form-panel"><div class="panel-heading"><div><p class="eyebrow">KEGIATAN KELAS</p><h3>Buat tugas baru</h3></div></div>
                        <?php if (!$subjects): ?><p class="muted">Belum ada mata pelajaran yang ditugaskan kepada Anda. Hubungi administrator.</p><?php else: ?>
                            <form method="post" class="form-grid">
                                <?= csrf_input() ?><input type="hidden" name="action" value="create_assignment"><input type="hidden" name="return_page" value="tasks">
                                <label>Mata pelajaran<select name="subject_id" required><?php foreach ($subjects as $subject): ?><option value="<?= h($subject['id']) ?>"><?= h($subject['code'] . ' · ' . $subject['name']) ?></option><?php endforeach; ?></select></label>
                                <label>Judul tugas<input name="title" required maxlength="160" placeholder="Contoh: Praktik konfigurasi jaringan"></label>
                                <label class="full-span">Petunjuk pengerjaan<textarea name="description" rows="3" required placeholder="Jelaskan tugas dan format pengumpulan..."></textarea></label>
                                <label>Batas pengumpulan<input type="datetime-local" name="due_date"></label>
                                <div class="full-span form-actions"><button class="button primary" type="submit">Publikasikan tugas</button></div>
                            </form>
                        <?php endif; ?>
                    </section>
                <?php endif; ?>
                <div class="section-title"><div><p class="eyebrow">KEGIATAN PEMBELAJARAN</p><h2><?= $user['role'] === 'siswa' ? 'Tugas untukmu' : 'Daftar tugas' ?></h2></div><span class="count-pill"><?= count($assignments) ?> tugas</span></div>
                <?php if (!$assignments): ?><div class="panel empty-state"><span>▣</span><strong>Belum ada tugas</strong><p>Tugas baru akan muncul di sini.</p></div><?php else: ?>
                    <div class="task-list"><?php foreach ($assignments as $assignment): $mySubmission = $studentSubmissions[$assignment['id']] ?? null; ?><article class="panel task-card"><div class="task-heading"><div><span class="subject-tag"><?= h($assignment['subject_name']) ?></span><h3><?= h($assignment['title']) ?></h3></div><?php if ($user['role'] === 'siswa'): ?><span class="status-tag <?= $mySubmission ? 'done' : 'pending' ?>"><?= $mySubmission ? 'Terkumpul' : 'Belum dikumpulkan' ?></span><?php endif; ?></div><p class="task-description"><?= nl2br(h($assignment['description'])) ?></p><div class="task-meta"><span>◷ Batas: <strong><?= h(format_date($assignment['due_date'])) ?></strong></span><span>Oleh <?= h($assignment['author_name'] ?? 'Pengajar') ?></span></div>
                        <?php if ($user['role'] === 'siswa'): ?>
                            <?php if ($mySubmission): ?><div class="submission-note">Berkas: <a href="download.php?id=<?= h($mySubmission['id']) ?>"><?= h($mySubmission['file_name']) ?></a><span> · dikirim <?= h(format_date($mySubmission['submitted_at'])) ?></span></div><?php endif; ?>
                            <form method="post" enctype="multipart/form-data" class="upload-form"><input type="hidden" name="csrf_token" value="<?= h(csrf_token()) ?>"><input type="hidden" name="action" value="submit_assignment"><input type="hidden" name="return_page" value="tasks"><input type="hidden" name="assignment_id" value="<?= h($assignment['id']) ?>"><label class="file-input"> <span>↑</span> <?= $mySubmission ? 'Ganti berkas' : 'Pilih berkas tugas' ?><input type="file" name="submission" accept=".pdf,.doc,.docx,.jpg,.jpeg,.png" required></label><small>PDF, DOC, DOCX, JPG, PNG · maks. 10 MB</small><button class="button primary small" type="submit"><?= $mySubmission ? 'Unggah ulang' : 'Kirim tugas' ?></button></form>
                        <?php endif; ?>
                    </article><?php endforeach; ?></div>
                <?php endif; ?>
                <?php if (in_array($user['role'], ['admin', 'guru'], true)): ?>
                    <div class="section-title section-gap"><div><p class="eyebrow">HASIL KERJA SISWA</p><h2>Pengumpulan & penilaian</h2></div><span class="count-pill"><?= $pendingCount ?> belum dinilai</span></div>
                    <?php if (!$submissions): ?><div class="panel empty-state"><span>↥</span><strong>Belum ada pengumpulan</strong><p>Pengumpulan siswa akan muncul di sini.</p></div><?php else: ?>
                        <div class="panel table-panel"><div class="table-wrap"><table><thead><tr><th>Siswa</th><th>Tugas / mapel</th><th>Berkas</th><th>Dikirim</th><th>Penilaian</th></tr></thead><tbody>
                            <?php foreach ($submissions as $submission): ?><tr><td><strong><?= h($submission['student_name']) ?></strong><small><?= h($submission['username']) ?></small></td><td><?= h($submission['assignment_title']) ?><small><?= h($submission['subject_name']) ?></small></td><td><a class="text-link" href="download.php?id=<?= h($submission['id']) ?>">Unduh berkas ↗</a></td><td><?= h(format_date($submission['submitted_at'])) ?></td><td><form method="post" class="grade-form"><input type="hidden" name="csrf_token" value="<?= h(csrf_token()) ?>"><input type="hidden" name="action" value="grade_submission"><input type="hidden" name="return_page" value="tasks"><input type="hidden" name="submission_id" value="<?= h($submission['id']) ?>"><input type="number" name="score" min="0" max="100" step="0.01" value="<?= $submission['score'] !== null ? h($submission['score']) : '' ?>" required placeholder="0–100" aria-label="Nilai"><input name="feedback" value="<?= h($submission['feedback'] ?? '') ?>" placeholder="Catatan untuk siswa" aria-label="Catatan"><button class="button primary small" type="submit">Simpan</button></form></td></tr><?php endforeach; ?>
                        </tbody></table></div></div>
                    <?php endif; ?>
                <?php endif; ?>

            <?php elseif ($page === 'grades'): ?>
                <div class="section-title"><div><p class="eyebrow">HASIL PEMBELAJARAN</p><h2><?= $user['role'] === 'siswa' ? 'Nilai saya' : 'Rekap nilai siswa' ?></h2></div><span class="count-pill"><?= count($grades) ?> penilaian</span></div>
                <?php if (!$grades): ?><div class="panel empty-state"><span>▥</span><strong>Belum ada nilai</strong><p>Nilai akan ditampilkan setelah guru selesai menilai tugas.</p></div><?php else: ?>
                    <div class="panel table-panel"><div class="table-wrap"><table><thead><tr><?php if ($user['role'] !== 'siswa'): ?><th>Siswa</th><?php endif; ?><th>Tugas</th><th>Mata pelajaran</th><th>Nilai</th><th>Umpan balik</th><th>Tanggal</th></tr></thead><tbody><?php foreach ($grades as $grade): ?><tr><?php if ($user['role'] !== 'siswa'): ?><td><?= h($grade['student_name']) ?></td><?php endif; ?><td><strong><?= h($grade['assignment_title']) ?></strong></td><td><?= h($grade['subject_name']) ?></td><td><span class="score-pill"><?= h(number_format((float) $grade['score'], 0)) ?></span></td><td><?= h($grade['feedback'] ?: '—') ?></td><td><?= h(format_date($grade['graded_at'])) ?></td></tr><?php endforeach; ?></tbody></table></div></div>
                <?php endif; ?>

            <?php elseif ($page === 'account'): ?>
                <section class="panel form-panel"><div class="panel-heading"><div><p class="eyebrow">PENGATURAN PROFIL</p><h3>Informasi akun</h3></div></div>
                    <div class="account-summary"><div class="avatar"><?= h(strtoupper(substr($user['name'], 0, 1))) ?></div><div><strong><?= h($user['name']) ?></strong><span>@<?= h($user['username']) ?> · <?= h($roleNames[$user['role']]) ?></span></div></div>
                </section>
                <section class="panel form-panel"><div class="panel-heading"><div><p class="eyebrow">KEAMANAN AKUN</p><h3>Ganti kata sandi</h3></div></div>
                    <form method="post" class="form-grid">
                        <?= csrf_input() ?><input type="hidden" name="action" value="change_password"><input type="hidden" name="return_page" value="account">
                        <label class="full-span">Kata sandi saat ini<input type="password" name="current_password" required autocomplete="current-password"></label>
                        <label>Kata sandi baru<input type="password" name="new_password" required minlength="8" autocomplete="new-password"></label>
                        <label>Konfirmasi kata sandi baru<input type="password" name="confirm_password" required minlength="8" autocomplete="new-password"></label>
                        <div class="full-span form-actions"><button class="button primary" type="submit">Perbarui kata sandi</button></div>
                    </form>
                </section>

            <?php elseif ($page === 'subjects'): ?>
                <section class="panel form-panel"><div class="panel-heading"><div><p class="eyebrow">KURIKULUM TJKT</p><h3>Tambah mata pelajaran</h3></div></div>
                    <?php $teachers = $contentQuery("SELECT id, name FROM users WHERE role = 'guru' ORDER BY name"); ?>
                    <form method="post" class="form-grid">
                        <?= csrf_input() ?><input type="hidden" name="action" value="create_subject"><input type="hidden" name="return_page" value="subjects">
                        <label>Nama mata pelajaran<input name="name" required placeholder="Contoh: Administrasi Infrastruktur Jaringan"></label><label>Kode mata pelajaran<input name="code" required placeholder="TJKT-02"></label>
                        <label class="full-span">Guru pengampu<select name="teacher_id"><option value="0">Belum ditentukan</option><?php foreach ($teachers as $teacher): ?><option value="<?= h($teacher['id']) ?>"><?= h($teacher['name']) ?></option><?php endforeach; ?></select></label>
                        <div class="full-span form-actions"><button class="button primary" type="submit">Tambah mata pelajaran</button></div>
                    </form>
                </section>
                <div class="section-title"><div><p class="eyebrow">DAFTAR KELAS</p><h2>Mata pelajaran</h2></div><span class="count-pill"><?= count($subjects) ?> mapel</span></div>
                <div class="panel table-panel"><div class="table-wrap"><table><thead><tr><th>Kode</th><th>Nama mata pelajaran</th><th>Guru pengampu</th><th></th></tr></thead><tbody><?php foreach ($subjects as $subject): ?><tr><td><span class="subject-tag"><?= h($subject['code']) ?></span></td><td><strong><?= h($subject['name']) ?></strong></td><td><?= h($subject['teacher_name'] ?? 'Belum ditentukan') ?></td><td><form method="post" onsubmit="return confirm('Hapus mata pelajaran ini beserta materi dan tugas terkait?')"><input type="hidden" name="csrf_token" value="<?= h(csrf_token()) ?>"><input type="hidden" name="action" value="delete_subject"><input type="hidden" name="return_page" value="subjects"><input type="hidden" name="id" value="<?= h($subject['id']) ?>"><button class="button danger small" type="submit">Hapus</button></form></td></tr><?php endforeach; ?></tbody></table></div></div>

            <?php elseif ($page === 'users'): ?>
                <section class="panel form-panel"><div class="panel-heading"><div><p class="eyebrow">AKSES PLATFORM</p><h3>Tambah akun pengguna</h3></div></div>
                    <form method="post" class="form-grid">
                        <?= csrf_input() ?><input type="hidden" name="action" value="create_user"><input type="hidden" name="return_page" value="users">
                        <label>Nama lengkap<input name="name" required placeholder="Nama pengguna"></label><label>Username<input name="username" required placeholder="username"></label>
                        <label>Kata sandi awal<input type="password" name="password" required minlength="6" placeholder="Minimal 6 karakter"></label><label>Peran<select name="role"><option value="siswa">Siswa</option><option value="guru">Guru</option><option value="admin">Administrator</option></select></label>
                        <div class="full-span form-actions"><button class="button primary" type="submit">Buat akun</button></div>
                    </form>
                </section>
                <?php $allUsers = $contentQuery('SELECT id, username, name, role, created_at FROM users ORDER BY CASE role WHEN "admin" THEN 1 WHEN "guru" THEN 2 ELSE 3 END, name'); ?>
                <div class="section-title"><div><p class="eyebrow">KOMUNITAS SEKOLAH</p><h2>Semua pengguna</h2></div><span class="count-pill"><?= count($allUsers) ?> akun</span></div>
                <div class="panel table-panel"><div class="table-wrap"><table><thead><tr><th>Pengguna</th><th>Username</th><th>Peran</th><th>Bergabung</th><th></th></tr></thead><tbody><?php foreach ($allUsers as $account): ?><tr><td><strong><?= h($account['name']) ?></strong></td><td><?= h($account['username']) ?></td><td><span class="role-tag <?= h($account['role']) ?>"><?= h($roleNames[$account['role']]) ?></span></td><td><?= h(date('d M Y', strtotime($account['created_at']))) ?></td><td><?php if ((int) $account['id'] !== (int) $user['id']): ?><form method="post" onsubmit="return confirm('Hapus akun <?= h($account['name']) ?>?')"><input type="hidden" name="csrf_token" value="<?= h(csrf_token()) ?>"><input type="hidden" name="action" value="delete_user"><input type="hidden" name="return_page" value="users"><input type="hidden" name="id" value="<?= h($account['id']) ?>"><button class="button danger small" type="submit">Hapus</button></form><?php else: ?><span class="muted">Akun Anda</span><?php endif; ?></td></tr><?php endforeach; ?></tbody></table></div></div>
            <?php endif; ?>
            <footer class="footer">Ruang TJKT <span>·</span> SMKN 2 Takalar</footer>
        </div>
    </main>
</div>
</body>
</html>
<?php
function csrf_input(): string
{
    return '<input type="hidden" name="csrf_token" value="' . h(csrf_token()) . '">';
}
