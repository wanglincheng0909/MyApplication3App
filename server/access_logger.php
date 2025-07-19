<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, User-Agent, X-Requested-With, X-App-Version, X-Platform, X-Device-Model');

// 处理预检请求
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    exit(0);
}

// 数据库配置
$db_file = 'access_logs.db';

// 创建SQLite数据库连接
try {
    $pdo = new PDO("sqlite:$db_file");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // 创建访问日志表
    $pdo->exec("CREATE TABLE IF NOT EXISTS access_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        ip_address TEXT,
        user_agent TEXT,
        device_type TEXT,
        platform TEXT,
        app_version TEXT,
        device_model TEXT,
        request_method TEXT,
        request_uri TEXT,
        country TEXT,
        city TEXT,
        isp TEXT,
        response_time INTEGER,
        status_code INTEGER,
        request_headers TEXT,
        additional_info TEXT
    )");
    
} catch(PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Database connection failed: ' . $e->getMessage()]);
    exit;
}

// 获取访问信息
function getClientInfo() {
    $info = [];
    
    // 获取真实IP地址
    $info['ip_address'] = getClientIP();
    
    // 获取User-Agent
    $info['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    
    // 获取自定义头部信息
    $info['app_version'] = $_SERVER['HTTP_X_APP_VERSION'] ?? 'Unknown';
    $info['platform'] = $_SERVER['HTTP_X_PLATFORM'] ?? 'Unknown';
    $info['device_model'] = $_SERVER['HTTP_X_DEVICE_MODEL'] ?? 'Unknown';
    $info['device_type'] = $_SERVER['HTTP_X_DEVICE_TYPE'] ?? 'Unknown';
    
    // 获取请求信息
    $info['request_method'] = $_SERVER['REQUEST_METHOD'];
    $info['request_uri'] = $_SERVER['REQUEST_URI'] ?? '';
    
    // 获取所有请求头
    $headers = [];
    foreach ($_SERVER as $key => $value) {
        if (strpos($key, 'HTTP_') === 0) {
            $header_name = str_replace('HTTP_', '', $key);
            $header_name = str_replace('_', '-', $header_name);
            $headers[$header_name] = $value;
        }
    }
    $info['request_headers'] = json_encode($headers);
    
    return $info;
}

// 获取客户端真实IP
function getClientIP() {
    $ip_keys = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];
    
    foreach ($ip_keys as $key) {
        if (!empty($_SERVER[$key])) {
            $ips = explode(',', $_SERVER[$key]);
            $ip = trim($ips[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $ip;
            }
        }
    }
    
    return $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
}

// 获取地理位置信息
function getLocationInfo($ip) {
    if ($ip === 'Unknown' || filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE) === false) {
        return ['country' => 'Unknown', 'city' => 'Unknown', 'isp' => 'Unknown'];
    }
    
    // 使用免费的IP地理位置API
    $apis = [
        "http://ip-api.com/json/{$ip}?fields=status,country,city,isp",
        "https://ipapi.co/{$ip}/json/",
        "http://www.geoplugin.net/json.gp?ip={$ip}"
    ];
    
    foreach ($apis as $api) {
        $context = stream_context_create([
            'http' => [
                'timeout' => 3,
                'user_agent' => 'MyApplication3-AccessLogger/1.0'
            ]
        ]);
        
        $response = @file_get_contents($api, false, $context);
        if ($response) {
            $data = json_decode($response, true);
            if ($data) {
                // 根据不同API格式解析
                if (isset($data['status']) && $data['status'] === 'success') {
                    // ip-api.com
                    return [
                        'country' => $data['country'] ?? 'Unknown',
                        'city' => $data['city'] ?? 'Unknown',
                        'isp' => $data['isp'] ?? 'Unknown'
                    ];
                } elseif (isset($data['country_name'])) {
                    // ipapi.co
                    return [
                        'country' => $data['country_name'] ?? 'Unknown',
                        'city' => $data['city'] ?? 'Unknown',
                        'isp' => $data['org'] ?? 'Unknown'
                    ];
                } elseif (isset($data['geoplugin_countryName'])) {
                    // geoplugin
                    return [
                        'country' => $data['geoplugin_countryName'] ?? 'Unknown',
                        'city' => $data['geoplugin_city'] ?? 'Unknown',
                        'isp' => $data['geoplugin_isp'] ?? 'Unknown'
                    ];
                }
            }
        }
    }
    
    return ['country' => 'Unknown', 'city' => 'Unknown', 'isp' => 'Unknown'];
}

// 记录访问日志
function logAccess($pdo, $info, $location, $response_time = 0, $status_code = 200) {
    $sql = "INSERT INTO access_logs (
        ip_address, user_agent, device_type, platform, app_version, device_model,
        request_method, request_uri, country, city, isp, response_time, status_code,
        request_headers, additional_info
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    
    $stmt = $pdo->prepare($sql);
    $stmt->execute([
        $info['ip_address'],
        $info['user_agent'],
        $info['device_type'],
        $info['platform'],
        $info['app_version'],
        $info['device_model'],
        $info['request_method'],
        $info['request_uri'],
        $location['country'],
        $location['city'],
        $location['isp'],
        $response_time,
        $status_code,
        $info['request_headers'],
        json_encode(['timestamp' => date('Y-m-d H:i:s.u')])
    ]);
    
    return $pdo->lastInsertId();
}

// 主处理逻辑
$start_time = microtime(true);

// 获取客户端信息
$client_info = getClientInfo();

// 获取地理位置信息
$location_info = getLocationInfo($client_info['ip_address']);

// 计算响应时间
$response_time = round((microtime(true) - $start_time) * 1000); // 毫秒

// 记录访问日志
try {
    $log_id = logAccess($pdo, $client_info, $location_info, $response_time, 200);
    
    // 读取并返回版本信息
    $version_file = '../version.json';
    if (file_exists($version_file)) {
        $version_data = file_get_contents($version_file);
        $version_json = json_decode($version_data, true);
        
        if ($version_json) {
            // 添加访问记录ID到响应中
            $version_json['_access_log_id'] = $log_id;
            $version_json['_server_time'] = date('Y-m-d H:i:s.u');
            $version_json['_response_time_ms'] = $response_time;
            
            echo json_encode($version_json, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        } else {
            http_response_code(500);
            echo json_encode(['error' => 'Invalid version file format']);
        }
    } else {
        http_response_code(404);
        echo json_encode(['error' => 'Version file not found']);
    }
    
} catch(Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Failed to log access: ' . $e->getMessage()]);
}
?>
