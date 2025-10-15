<?php
class User {
    private $conn;
    private $table_name = "users"; // Changed to plural (best practice)

    public $id;
    public $username;
    public $email;
    public $password;
    public $role;
    public $is_active;
    public $created_at;
    public $updated_at;

    public function __construct($db) {
        $this->conn = $db;
    }

    // Method untuk validasi input
    private function validateInput() {
        $errors = [];

        // Validasi username
        if (empty($this->username) || strlen($this->username) < 3) {
            $errors[] = "Username harus minimal 3 karakter";
        } elseif (!preg_match('/^[a-zA-Z0-9_]+$/', $this->username)) {
            $errors[] = "Username hanya boleh mengandung huruf, angka, dan underscore";
        }

        // Validasi email
        if (empty($this->email) || !filter_var($this->email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = "Format email tidak valid";
        }

        // Validasi password
        if (empty($this->password) || strlen($this->password) < 6) {
            $errors[] = "Password harus minimal 6 karakter";
        }

        // Validasi role
        $allowed_roles = ['user', 'admin'];
        if (!empty($this->role) && !in_array($this->role, $allowed_roles)) {
            $errors[] = "Role tidak valid";
        }

        return $errors;
    }

    // Method untuk sign up
    public function signup() {
        try {
            // Validasi input
            $validation_errors = $this->validateInput();
            if (!empty($validation_errors)) {
                return array("success" => false, "message" => implode(", ", $validation_errors));
            }

            // Cek apakah username atau email sudah ada
            $check_query = "SELECT id FROM " . $this->table_name . " WHERE username = :username OR email = :email";
            $check_stmt = $this->conn->prepare($check_query);
            $check_stmt->bindParam(":username", $this->username);
            $check_stmt->bindParam(":email", $this->email);
            $check_stmt->execute();

            if ($check_stmt->rowCount() > 0) {
                return array("success" => false, "message" => "Username atau email sudah terdaftar");
            }

            // Hash password
            $hashed_password = password_hash($this->password, PASSWORD_DEFAULT);
            
            // Set default role jika tidak diset
            if (empty($this->role)) {
                $this->role = 'user';
            }

            // Query insert dengan created_at
            $query = "INSERT INTO " . $this->table_name . " 
                     (username, email, password, role, created_at) 
                     VALUES 
                     (:username, :email, :password, :role, NOW())";

            $stmt = $this->conn->prepare($query);

            // Sanitize data
            $this->username = htmlspecialchars(strip_tags($this->username));
            $this->email = htmlspecialchars(strip_tags($this->email));

            // Bind parameters
            $stmt->bindParam(":username", $this->username);
            $stmt->bindParam(":email", $this->email);
            $stmt->bindParam(":password", $hashed_password);
            $stmt->bindParam(":role", $this->role);

            if ($stmt->execute()) {
                $this->id = $this->conn->lastInsertId();
                return array(
                    "success" => true, 
                    "message" => "Pendaftaran berhasil!",
                    "user_id" => $this->id
                );
            } else {
                return array("success" => false, "message" => "Terjadi kesalahan saat mendaftar");
            }

        } catch(PDOException $exception) {
            error_log("Signup Error: " . $exception->getMessage());
            return array("success" => false, "message" => "Terjadi kesalahan sistem");
        }
    }

    // Method untuk login
    public function login() {
        try {
            if (empty($this->username) || empty($this->password)) {
                return array("success" => false, "message" => "Username dan password harus diisi");
            }

            $query = "SELECT id, username, email, password, role, is_active 
                     FROM " . $this->table_name . " 
                     WHERE (username = :username OR email = :username)";

            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(":username", $this->username);
            $stmt->execute();

            if ($stmt->rowCount() == 1) {
                $row = $stmt->fetch(PDO::FETCH_ASSOC);
                
                // Cek jika akun aktif
                if (!$row['is_active']) {
                    return array("success" => false, "message" => "Akun tidak aktif. Silakan hubungi administrator.");
                }
                
                // Verifikasi password
                if (password_verify($this->password, $row['password'])) {
                    // Start session jika belum started
                    if (session_status() == PHP_SESSION_NONE) {
                        session_start();
                    }
                    
                    // Regenerate session ID untuk security
                    session_regenerate_id(true);
                    
                    // Simpan data user di session
                    $_SESSION['user_id'] = $row['id'];
                    $_SESSION['username'] = $row['username'];
                    $_SESSION['email'] = $row['email'];
                    $_SESSION['role'] = $row['role'];
                    $_SESSION['logged_in'] = true;
                    
                    // Update last login
                    $this->updateLastLogin($row['id']);
                    
                    return array(
                        "success" => true, 
                        "message" => "Login berhasil!",
                        "user" => array(
                            "id" => $row['id'],
                            "username" => $row['username'],
                            "email" => $row['email'],
                            "role" => $row['role']
                        )
                    );
                } else {
                    return array("success" => false, "message" => "Password salah");
                }
            } else {
                return array("success" => false, "message" => "Username/email tidak ditemukan");
            }

        } catch(PDOException $exception) {
            error_log("Login Error: " . $exception->getMessage());
            return array("success" => false, "message" => "Terjadi kesalahan sistem");
        }
    }

    // Method untuk update last login
    private function updateLastLogin($user_id) {
        try {
            $query = "UPDATE " . $this->table_name . " SET updated_at = NOW() WHERE id = :id";
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(":id", $user_id);
            $stmt->execute();
        } catch(PDOException $e) {
            error_log("Update Last Login Error: " . $e->getMessage());
        }
    }

    // Method untuk mendapatkan user by ID
    public function getUserById($user_id) {
        try {
            $query = "SELECT id, username, email, role, is_active, created_at, updated_at 
                     FROM " . $this->table_name . " 
                     WHERE id = :id";
            
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(":id", $user_id);
            $stmt->execute();
            
            if ($stmt->rowCount() == 1) {
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
                return array("success" => true, "user" => $user);
            } else {
                return array("success" => false, "message" => "User tidak ditemukan");
            }
            
        } catch(PDOException $exception) {
            error_log("Get User Error: " . $exception->getMessage());
            return array("success" => false, "message" => "Terjadi kesalahan sistem");
        }
    }

    // Method untuk mendapatkan semua users (admin only)
    public function getAllUsers($page = 1, $limit = 10) {
        try {
            $offset = ($page - 1) * $limit;
            
            $query = "SELECT id, username, email, role, is_active, created_at, updated_at 
                     FROM " . $this->table_name . " 
                     ORDER BY created_at DESC 
                     LIMIT :limit OFFSET :offset";
            
            $count_query = "SELECT COUNT(*) as total FROM " . $this->table_name;
            
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(":limit", $limit, PDO::PARAM_INT);
            $stmt->bindParam(":offset", $offset, PDO::PARAM_INT);
            $stmt->execute();
            
            $users = array();
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                $users[] = $row;
            }
            
            // Get total count for pagination
            $count_stmt = $this->conn->prepare($count_query);
            $count_stmt->execute();
            $total = $count_stmt->fetch(PDO::FETCH_ASSOC)['total'];
            
            return array(
                "success" => true, 
                "users" => $users,
                "pagination" => [
                    "page" => $page,
                    "limit" => $limit,
                    "total" => $total,
                    "total_pages" => ceil($total / $limit)
                ]
            );
            
        } catch(PDOException $exception) {
            error_log("Get All Users Error: " . $exception->getMessage());
            return array("success" => false, "message" => "Terjadi kesalahan sistem");
        }
    }

    // Method untuk update user profile (for own account)
    public function updateProfile($data) {
        try {
            if (session_status() == PHP_SESSION_NONE) {
                session_start();
            }
            
            $user_id = $_SESSION['user_id'];
            
            $update_fields = array();
            $params = array(":id" => $user_id);

            if (isset($data['username']) && !empty($data['username'])) {
                // Check if username already exists (excluding current user)
                $check_username = $this->conn->prepare("SELECT id FROM " . $this->table_name . " WHERE username = :username AND id != :id");
                $check_username->bindParam(":username", $data['username']);
                $check_username->bindParam(":id", $user_id);
                $check_username->execute();
                
                if ($check_username->rowCount() > 0) {
                    return array("success" => false, "message" => "Username sudah digunakan");
                }
                
                $update_fields[] = "username = :username";
                $params[":username"] = htmlspecialchars(strip_tags($data['username']));
            }

            if (isset($data['email']) && !empty($data['email'])) {
                // Check if email already exists (excluding current user)
                $check_email = $this->conn->prepare("SELECT id FROM " . $this->table_name . " WHERE email = :email AND id != :id");
                $check_email->bindParam(":email", $data['email']);
                $check_email->bindParam(":id", $user_id);
                $check_email->execute();
                
                if ($check_email->rowCount() > 0) {
                    return array("success" => false, "message" => "Email sudah digunakan");
                }
                
                if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
                    return array("success" => false, "message" => "Format email tidak valid");
                }
                
                $update_fields[] = "email = :email";
                $params[":email"] = htmlspecialchars(strip_tags($data['email']));
            }

            if (count($update_fields) > 0) {
                $update_fields[] = "updated_at = NOW()";
                
                $query = "UPDATE " . $this->table_name . " SET " . implode(", ", $update_fields) . " WHERE id = :id";
                $stmt = $this->conn->prepare($query);
                
                if ($stmt->execute($params)) {
                    // Update session data jika username/email diubah
                    if (isset($data['username'])) {
                        $_SESSION['username'] = $data['username'];
                    }
                    if (isset($data['email'])) {
                        $_SESSION['email'] = $data['email'];
                    }
                    
                    return array("success" => true, "message" => "Profile berhasil diupdate");
                } else {
                    return array("success" => false, "message" => "Gagal mengupdate profile");
                }
            } else {
                return array("success" => false, "message" => "Tidak ada data yang diupdate");
            }

        } catch(PDOException $exception) {
            error_log("Update Profile Error: " . $exception->getMessage());
            return array("success" => false, "message" => "Terjadi kesalahan sistem");
        }
    }

    // Method untuk change password
    public function changePassword($current_password, $new_password) {
        try {
            if (session_status() == PHP_SESSION_NONE) {
                session_start();
            }
            
            $user_id = $_SESSION['user_id'];
            
            // Get current password hash
            $query = "SELECT password FROM " . $this->table_name . " WHERE id = :id";
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(":id", $user_id);
            $stmt->execute();
            
            if ($stmt->rowCount() == 1) {
                $row = $stmt->fetch(PDO::FETCH_ASSOC);
                
                // Verify current password
                if (!password_verify($current_password, $row['password'])) {
                    return array("success" => false, "message" => "Password saat ini salah");
                }
                
                // Validate new password
                if (strlen($new_password) < 6) {
                    return array("success" => false, "message" => "Password baru harus minimal 6 karakter");
                }
                
                // Hash new password
                $new_password_hash = password_hash($new_password, PASSWORD_DEFAULT);
                
                // Update password
                $update_query = "UPDATE " . $this->table_name . " SET password = :password, updated_at = NOW() WHERE id = :id";
                $update_stmt = $this->conn->prepare($update_query);
                $update_stmt->bindParam(":password", $new_password_hash);
                $update_stmt->bindParam(":id", $user_id);
                
                if ($update_stmt->execute()) {
                    return array("success" => true, "message" => "Password berhasil diubah");
                } else {
                    return array("success" => false, "message" => "Gagal mengubah password");
                }
            } else {
                return array("success" => false, "message" => "User tidak ditemukan");
            }

        } catch(PDOException $exception) {
            error_log("Change Password Error: " . $exception->getMessage());
            return array("success" => false, "message" => "Terjadi kesalahan sistem");
        }
    }

    // Method untuk update user (admin only) - improved version
    public function updateUser($user_id, $data) {
        try {
            // Cek apakah user ada
            $user_check = $this->getUserById($user_id);
            if (!$user_check['success']) {
                return $user_check;
            }

            $update_fields = array();
            $params = array(":id" => $user_id);

            // Validasi dan sanitasi data
            if (isset($data['username']) && !empty($data['username'])) {
                // Check username uniqueness
                $check_username = $this->conn->prepare("SELECT id FROM " . $this->table_name . " WHERE username = :username AND id != :id");
                $check_username->execute([":username" => $data['username'], ":id" => $user_id]);
                if ($check_username->rowCount() > 0) {
                    return array("success" => false, "message" => "Username sudah digunakan");
                }
                $update_fields[] = "username = :username";
                $params[":username"] = htmlspecialchars(strip_tags($data['username']));
            }

            if (isset($data['email']) && !empty($data['email'])) {
                // Check email uniqueness
                $check_email = $this->conn->prepare("SELECT id FROM " . $this->table_name . " WHERE email = :email AND id != :id");
                $check_email->execute([":email" => $data['email'], ":id" => $user_id]);
                if ($check_email->rowCount() > 0) {
                    return array("success" => false, "message" => "Email sudah digunakan");
                }
                if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
                    return array("success" => false, "message" => "Format email tidak valid");
                }
                $update_fields[] = "email = :email";
                $params[":email"] = htmlspecialchars(strip_tags($data['email']));
            }

            if (isset($data['role']) && in_array($data['role'], ['user', 'admin'])) {
                $update_fields[] = "role = :role";
                $params[":role"] = $data['role'];
            }

            if (isset($data['is_active'])) {
                $update_fields[] = "is_active = :is_active";
                $params[":is_active"] = filter_var($data['is_active'], FILTER_VALIDATE_BOOLEAN) ? 1 : 0;
            }

            if (count($update_fields) > 0) {
                $update_fields[] = "updated_at = NOW()";
                
                $query = "UPDATE " . $this->table_name . " SET " . implode(", ", $update_fields) . " WHERE id = :id";
                $stmt = $this->conn->prepare($query);

                if ($stmt->execute($params)) {
                    return array("success" => true, "message" => "User berhasil diupdate");
                } else {
                    return array("success" => false, "message" => "Gagal mengupdate user");
                }
            } else {
                return array("success" => false, "message" => "Tidak ada data yang diupdate");
            }

        } catch(PDOException $exception) {
            error_log("Update User Error: " . $exception->getMessage());
            return array("success" => false, "message" => "Terjadi kesalahan sistem");
        }
    }

    // Method untuk delete user (admin only) - improved
    public function deleteUser($user_id) {
        try {
            // Jangan izinkan admin menghapus dirinya sendiri
            if (session_status() == PHP_SESSION_NONE) {
                session_start();
            }
            
            if ($user_id == $_SESSION['user_id']) {
                return array("success" => false, "message" => "Tidak dapat menghapus akun sendiri");
            }

            // Cek apakah user exists
            $user_check = $this->getUserById($user_id);
            if (!$user_check['success']) {
                return $user_check;
            }

            $query = "DELETE FROM " . $this->table_name . " WHERE id = :id";
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(":id", $user_id);

            if ($stmt->execute()) {
                return array("success" => true, "message" => "User berhasil dihapus");
            } else {
                return array("success" => false, "message" => "Gagal menghapus user");
            }

        } catch(PDOException $exception) {
            error_log("Delete User Error: " . $exception->getMessage());
            return array("success" => false, "message" => "Terjadi kesalahan sistem");
        }
    }

    // Method untuk cek session - improved
    public static function checkAuth() {
        if (session_status() == PHP_SESSION_NONE) {
            session_start();
        }
        
        if (isset($_SESSION['user_id'], $_SESSION['logged_in']) && $_SESSION['logged_in'] === true) {
            return array(
                "authenticated" => true,
                "user" => array(
                    "id" => $_SESSION['user_id'],
                    "username" => $_SESSION['username'],
                    "email" => $_SESSION['email'],
                    "role" => $_SESSION['role']
                )
            );
        } else {
            return array("authenticated" => false);
        }
    }

    // Method untuk cek apakah user adalah admin
    public static function isAdmin() {
        $auth = self::checkAuth();
        return $auth['authenticated'] && $auth['user']['role'] === 'admin';
    }

    // Method untuk logout - improved
    public static function logout() {
        if (session_status() == PHP_SESSION_NONE) {
            session_start();
        }
        
        // Clear all session variables
        $_SESSION = array();
        
        // Destroy session cookie
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000,
                $params["path"], $params["domain"],
                $params["secure"], $params["httponly"]
            );
        }
        
        session_destroy();
        
        return array("success" => true, "message" => "Logout berhasil");
    }
}
?>