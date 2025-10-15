<?php
// api.php
header("Content-Type: application/json; charset=UTF-8");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS, PUT, DELETE");
header("Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With, X-API-KEY");

// Handle preflight OPTIONS request
if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Include config dan class User
include_once 'config.php';
include_once 'User.php';

// Inisialisasi database dan user object
try {
    $database = new Database();
    $db = $database->getConnection();
    $user = new User($db);
} catch (Exception $e) {
    http_response_code(503);
    echo json_encode(array("success" => false, "message" => "Service unavailable: Database connection failed"));
    exit();
}

// Get request method
$method = $_SERVER['REQUEST_METHOD'];

// Helper function untuk mendapatkan authorization header
function getAuthorizationHeader() {
    $headers = null;
    if (isset($_SERVER['Authorization'])) {
        $headers = trim($_SERVER['Authorization']);
    } elseif (isset($_SERVER['HTTP_AUTHORIZATION'])) {
        $headers = trim($_SERVER['HTTP_AUTHORIZATION']);
    } elseif (function_exists('apache_request_headers')) {
        $requestHeaders = apache_request_headers();
        $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));
        if (isset($requestHeaders['Authorization'])) {
            $headers = trim($requestHeaders['Authorization']);
        }
    }
    return $headers;
}

// Helper function untuk get bearer token
function getBearerToken() {
    $headers = getAuthorizationHeader();
    if (!empty($headers)) {
        if (preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
            return $matches[1];
        }
    }
    return null;
}

// Helper function untuk validate JSON input
function getJsonInput() {
    $input = file_get_contents("php://input");
    if (empty($input)) {
        return null;
    }
    
    $data = json_decode($input, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        return null;
    }
    
    return $data;
}

// Helper function untuk send response
function sendResponse($success, $message = '', $data = null, $httpCode = 200) {
    http_response_code($httpCode);
    $response = array("success" => $success);
    
    if ($message) {
        $response["message"] = $message;
    }
    
    if ($data !== null) {
        $response["data"] = $data;
    }
    
    echo json_encode($response);
    exit();
}

// Handle request berdasarkan method
try {
    switch($method) {
        case 'POST':
            $data = getJsonInput();
            if ($data === null) {
                sendResponse(false, "Invalid JSON input", null, 400);
            }

            if(!isset($data['action'])) {
                sendResponse(false, "Action tidak ditemukan", null, 400);
            }

            switch($data['action']) {
                case 'signup':
                    // Validasi input
                    if(empty($data['username']) || empty($data['email']) || empty($data['password'])) {
                        sendResponse(false, "Semua field harus diisi", null, 400);
                    }

                    $user->username = $data['username'];
                    $user->email = $data['email'];
                    $user->password = $data['password'];
                    $user->role = isset($data['role']) ? $data['role'] : 'user';
                    
                    $result = $user->signup();
                    if ($result['success']) {
                        sendResponse(true, $result['message'], array('user_id' => $result['user_id']), 201);
                    } else {
                        sendResponse(false, $result['message'], null, 400);
                    }
                    break;
                    
                case 'login':
                    // Validasi input
                    if(empty($data['username']) || empty($data['password'])) {
                        sendResponse(false, "Username dan password harus diisi", null, 400);
                    }

                    $user->username = $data['username'];
                    $user->password = $data['password'];
                    
                    $result = $user->login();
                    if ($result['success']) {
                        sendResponse(true, $result['message'], $result['user']);
                    } else {
                        sendResponse(false, $result['message'], null, 401);
                    }
                    break;
                    
                case 'logout':
                    $result = User::logout();
                    sendResponse(true, $result['message']);
                    break;

                case 'update_profile':
                    $auth = User::checkAuth();
                    if (!$auth['authenticated']) {
                        sendResponse(false, "Unauthorized", null, 401);
                    }

                    $result = $user->updateProfile($data);
                    if ($result['success']) {
                        sendResponse(true, $result['message']);
                    } else {
                        sendResponse(false, $result['message'], null, 400);
                    }
                    break;

                case 'change_password':
                    $auth = User::checkAuth();
                    if (!$auth['authenticated']) {
                        sendResponse(false, "Unauthorized", null, 401);
                    }

                    if(empty($data['current_password']) || empty($data['new_password'])) {
                        sendResponse(false, "Current password dan new password harus diisi", null, 400);
                    }

                    $result = $user->changePassword($data['current_password'], $data['new_password']);
                    if ($result['success']) {
                        sendResponse(true, $result['message']);
                    } else {
                        sendResponse(false, $result['message'], null, 400);
                    }
                    break;
                    
                default:
                    sendResponse(false, "Action tidak valid", null, 400);
            }
            break;
            
        case 'GET':
            if(!isset($_GET['action'])) {
                sendResponse(false, "Action tidak ditemukan", null, 400);
            }

            switch($_GET['action']) {
                case 'check_auth':
                    $result = User::checkAuth();
                    if ($result['authenticated']) {
                        sendResponse(true, "Authenticated", $result['user']);
                    } else {
                        sendResponse(false, "Not authenticated", null, 401);
                    }
                    break;

                case 'get_profile':
                    $auth = User::checkAuth();
                    if (!$auth['authenticated']) {
                        sendResponse(false, "Unauthorized", null, 401);
                    }

                    $result = $user->getUserById($auth['user']['id']);
                    if ($result['success']) {
                        sendResponse(true, "Profile retrieved", $result['user']);
                    } else {
                        sendResponse(false, $result['message'], null, 404);
                    }
                    break;
                    
                case 'get_users':
                    // Cek apakah user adalah admin
                    if (!User::isAdmin()) {
                        sendResponse(false, "Akses ditolak. Hanya admin yang dapat mengakses.", null, 403);
                    }
                    
                    $page = isset($_GET['page']) ? intval($_GET['page']) : 1;
                    $limit = isset($_GET['limit']) ? intval($_GET['limit']) : 10;
                    
                    // Validate pagination parameters
                    if ($page < 1) $page = 1;
                    if ($limit < 1 || $limit > 100) $limit = 10;
                    
                    $result = $user->getAllUsers($page, $limit);
                    if ($result['success']) {
                        sendResponse(true, "Users retrieved", $result);
                    } else {
                        sendResponse(false, $result['message'], null, 500);
                    }
                    break;

                case 'get_user':
                    // Cek apakah user adalah admin
                    if (!User::isAdmin()) {
                        sendResponse(false, "Akses ditolak. Hanya admin yang dapat mengakses.", null, 403);
                    }

                    if(!isset($_GET['user_id'])) {
                        sendResponse(false, "User ID tidak ditemukan", null, 400);
                    }

                    $result = $user->getUserById($_GET['user_id']);
                    if ($result['success']) {
                        sendResponse(true, "User retrieved", $result['user']);
                    } else {
                        sendResponse(false, $result['message'], null, 404);
                    }
                    break;
                    
                default:
                    sendResponse(false, "Action tidak valid", null, 400);
            }
            break;
            
        case 'PUT':
            $data = getJsonInput();
            if ($data === null) {
                sendResponse(false, "Invalid JSON input", null, 400);
            }

            if(!isset($data['action'])) {
                sendResponse(false, "Action tidak ditemukan", null, 400);
            }

            switch($data['action']) {
                case 'update_user':
                    // Cek apakah user adalah admin
                    if (!User::isAdmin()) {
                        sendResponse(false, "Akses ditolak. Hanya admin yang dapat mengakses.", null, 403);
                    }
                    
                    if(!isset($data['user_id'])) {
                        sendResponse(false, "User ID tidak ditemukan", null, 400);
                    }

                    $result = $user->updateUser($data['user_id'], $data);
                    if ($result['success']) {
                        sendResponse(true, $result['message']);
                    } else {
                        sendResponse(false, $result['message'], null, 400);
                    }
                    break;

                default:
                    sendResponse(false, "Action tidak valid", null, 400);
            }
            break;
            
        case 'DELETE':
            if(!isset($_GET['action'])) {
                sendResponse(false, "Action tidak ditemukan", null, 400);
            }

            switch($_GET['action']) {
                case 'delete_user':
                    // Cek apakah user adalah admin
                    if (!User::isAdmin()) {
                        sendResponse(false, "Akses ditolak. Hanya admin yang dapat mengakses.", null, 403);
                    }
                    
                    if(!isset($_GET['user_id'])) {
                        sendResponse(false, "User ID tidak ditemukan", null, 400);
                    }

                    $result = $user->deleteUser($_GET['user_id']);
                    if ($result['success']) {
                        sendResponse(true, $result['message']);
                    } else {
                        sendResponse(false, $result['message'], null, 400);
                    }
                    break;

                default:
                    sendResponse(false, "Action tidak valid", null, 400);
            }
            break;
            
        default:
            sendResponse(false, "Method tidak diizinkan", null, 405);
    }
} catch (Exception $e) {
    error_log("API Error: " . $e->getMessage());
    sendResponse(false, "Internal server error", null, 500);
}
?>