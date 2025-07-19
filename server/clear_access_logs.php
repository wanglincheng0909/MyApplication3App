<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    exit;
}

$db_file = 'access_logs.db';

try {
    $pdo = new PDO("sqlite:$db_file");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // 获取清除前的记录数
    $stmt = $pdo->query("SELECT COUNT(*) as count FROM access_logs");
    $beforeCount = $stmt->fetch(PDO::FETCH_ASSOC)['count'];
    
    // 清除所有访问记录
    $pdo->exec("DELETE FROM access_logs");
    
    // 重置自增ID
    $pdo->exec("DELETE FROM sqlite_sequence WHERE name='access_logs'");
    
    // 优化数据库
    $pdo->exec("VACUUM");
    
    echo json_encode([
        'success' => true,
        'message' => "成功清除 {$beforeCount} 条访问记录",
        'cleared_count' => $beforeCount
    ]);
    
} catch(PDOException $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => 'Database error: ' . $e->getMessage()
    ]);
}
?>
