<?php
class Database {
    private $host = "localhost";
    private $db_name = "financial_management";
    private $username = "root";
    private $password = "";
    public $conn;

    public function getConnection() {
        $this->conn = null;
        
        try {
            // Tambahkan port dan charset yang lebih lengkap
            $this->conn = new PDO(
                "mysql:host=" . $this->host . 
                ";port=3306;" . // Default port MySQL
                "dbname=" . $this->db_name . 
                ";charset=utf8mb4", 
                $this->username, 
                $this->password,
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false
                ]
            );
            
        } catch(PDOException $exception) {
            // Log error jangan tampilkan ke user
            error_log("Connection error: " . $exception->getMessage());
            throw new Exception("Database connection failed");
        }
        
        return $this->conn;
    }
}
?>