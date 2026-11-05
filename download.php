<?php
declare(strict_types=1);
require __DIR__ . DIRECTORY_SEPARATOR . 'bootstrap.php';

$user = current_user();
if (!$user) {
    http_response_code(401);
    exit('Silakan masuk terlebih dahulu.');
}

$statement = $db->prepare(
    'SELECT s.file_name, s.stored_name, s.student_id, sub.teacher_id
     FROM submissions s JOIN assignments a ON a.id = s.assignment_id
     JOIN subjects sub ON sub.id = a.subject_id WHERE s.id = ?'
);
$statement->execute([(int) ($_GET['id'] ?? 0)]);
$file = $statement->fetch();
if (!$file || ($user['role'] !== 'admin' && (int) $file['student_id'] !== (int) $user['id'] && ($user['role'] !== 'guru' || (int) $file['teacher_id'] !== (int) $user['id']))) {
    http_response_code(404);
    exit('Berkas tidak ditemukan.');
}

$path = __DIR__ . DIRECTORY_SEPARATOR . 'storage' . DIRECTORY_SEPARATOR . 'uploads' . DIRECTORY_SEPARATOR . basename($file['stored_name']);
if (!is_file($path)) {
    http_response_code(404);
    exit('Berkas tidak tersedia.');
}

header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="' . str_replace(['"', "\r", "\n"], '', basename($file['file_name'])) . '"');
header('Content-Length: ' . filesize($path));
readfile($path);
