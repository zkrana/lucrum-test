<?php
class Database {
    private $host = '127.0.0.1';
    private $db_name = 'lucrum_db';
    private $username = 'root';
    private $password = '';
    private $conn;

    public function getConnection() {
        $this->conn = null;

        try {
            $dsn = "mysql:host=" . $this->host . ";dbname=" . $this->db_name;
            error_log("Attempting to connect to database: " . $dsn);
            
            $this->conn = new PDO($dsn, $this->username, $this->password);
            $this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->conn->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
            
            error_log("Database connection established successfully");
            return $this->conn;
        } catch(PDOException $e) {
            error_log("Database Connection Error: " . $e->getMessage());
            error_log("Error Code: " . $e->getCode());
            error_log("Error File: " . $e->getFile());
            error_log("Error Line: " . $e->getLine());
            error_log("Error Trace: " . $e->getTraceAsString());
            throw new PDOException("Database Connection Error: " . $e->getMessage());
        }
    }
}
?>