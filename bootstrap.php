<?php
declare(strict_types=1);

date_default_timezone_set('Asia/Makassar');

const APP_NAME = 'Ruang TJKT';
const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;

$storagePath = __DIR__ . DIRECTORY_SEPARATOR . 'storage';
if (!is_dir($storagePath) && !mkdir($storagePath, 0775, true) && !is_dir($storagePath)) {
    throw new RuntimeException('Folder penyimpanan aplikasi tidak dapat dibuat.');
}

$db = new PDO('sqlite:' . $storagePath . DIRECTORY_SEPARATOR . 'lms.sqlite');
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
$db->exec('PRAGMA foreign_keys = ON');
$db->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'guru', 'siswa')),
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS subjects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    code TEXT NOT NULL UNIQUE,
    teacher_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS materials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    link TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    due_date TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assignment_id INTEGER NOT NULL REFERENCES assignments(id) ON DELETE CASCADE,
    student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    file_name TEXT NOT NULL,
    stored_name TEXT NOT NULL,
    submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (assignment_id, student_id)
);
CREATE TABLE IF NOT EXISTS grades (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    submission_id INTEGER NOT NULL UNIQUE REFERENCES submissions(id) ON DELETE CASCADE,
    teacher_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    score REAL NOT NULL CHECK (score >= 0 AND score <= 100),
    feedback TEXT NOT NULL DEFAULT '',
    graded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
SQL);

$seedUsers = [
    ['admin', 'Administrator', 'admin'],
    ['guru', 'Guru TJKT', 'guru'],
    ['siswa', 'Siswa TJKT', 'siswa'],
];
$insertUser = $db->prepare('INSERT OR IGNORE INTO users (username, name, role, password_hash) VALUES (?, ?, ?, ?)');
foreach ($seedUsers as [$username, $name, $role]) {
    $insertUser->execute([$username, $name, $role, password_hash($username, PASSWORD_DEFAULT)]);
}

$teacherId = $db->query("SELECT id FROM users WHERE username = 'guru'")->fetchColumn();
$seedSubject = $db->prepare('INSERT OR IGNORE INTO subjects (name, code, teacher_id) VALUES (?, ?, ?)');
$seedSubject->execute(['Dasar TJKT', 'TJKT-01', $teacherId ?: null]);

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_set_cookie_params([
        'httponly' => true,
        'samesite' => 'Lax',
        'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    ]);
    session_start();
}

function h(string|int|float|null $value): string
{
    return htmlspecialchars((string) ($value ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function current_user(): ?array
{
    return $_SESSION['user'] ?? null;
}

function require_login(): array
{
    $user = current_user();
    if (!$user) {
        throw new RuntimeException('Silakan masuk terlebih dahulu.');
    }
    return $user;
}

function require_role(array $roles): array
{
    $user = require_login();
    if (!in_array($user['role'], $roles, true)) {
        throw new RuntimeException('Anda tidak memiliki izin untuk melakukan tindakan ini.');
    }
    return $user;
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf(): void
{
    $submitted = $_POST['csrf_token'] ?? '';
    if (!is_string($submitted) || !hash_equals(csrf_token(), $submitted)) {
        throw new RuntimeException('Sesi formulir tidak valid. Muat ulang halaman lalu coba kembali.');
    }
}

function flash(string $message, string $type = 'success'): void
{
    $_SESSION['flash'] = ['message' => $message, 'type' => $type];
}

function go(string $page): never
{
    header('Location: index.php?page=' . rawurlencode($page));
    exit;
}

function can_access_subject(PDO $db, array $user, int $subjectId): bool
{
    if ($user['role'] === 'admin') {
        return true;
    }
    if ($user['role'] !== 'guru') {
        return false;
    }
    $statement = $db->prepare('SELECT 1 FROM subjects WHERE id = ? AND teacher_id = ?');
    $statement->execute([$subjectId, $user['id']]);
    return (bool) $statement->fetchColumn();
}

function format_date(?string $date): string
{
    if (!$date) {
        return 'Tidak ditentukan';
    }
    $timestamp = strtotime($date);
    return $timestamp ? date('d M Y, H:i', $timestamp) : h($date);
}
