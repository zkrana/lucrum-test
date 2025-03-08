<?php
require_once '../core/BaseApi.php';
require_once '../config/database.php';

function generateUUID() {
    return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
        mt_rand(0, 0xffff), mt_rand(0, 0xffff),
        mt_rand(0, 0xffff),
        mt_rand(0, 0x0fff) | 0x4000,
        mt_rand(0, 0x3fff) | 0x8000,
        mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
    );
}

class RegisterManualController extends BaseApi {
    private $db;
    private $conn;

    public function __construct() {
        try {
            $this->db = new Database();
            $this->conn = $this->db->getConnection();
            if (!$this->conn) {
                throw new PDOException("Failed to establish database connection");
            }
            $this->cors();
        } catch (PDOException $e) {
            $this->sendError($e->getMessage(), 500);
        }
    }

    public function register() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            $this->sendError('Method not allowed', 405);
        }
    
        $data = $this->getRequestBody();
        
        if (!isset($data['email']) || empty($data['email'])) {
            $this->sendError('Email is required', 400);
        }
        if (!isset($data['name']) || empty($data['name'])) {
            $this->sendError('Name is required', 400);
        }
        if (!isset($data['password']) || empty($data['password'])) {
            $this->sendError('Password is required', 400);
        }

        try {
            // Check if user already exists
            $stmt = $this->conn->prepare('SELECT id FROM User WHERE email = ?');
            $stmt->execute([$data['email']]);
            if ($stmt->fetch()) {
                $this->sendError('User already exists', 400);
            }
    
            $this->conn->beginTransaction();
    
            // Generate UUIDs
            $userId = generateUUID();
            $accountId = generateUUID();
    
            // Hash the password
            $hashedPassword = password_hash($data['password'], PASSWORD_DEFAULT);

            // Insert into User table
            $stmt = $this->conn->prepare(
                'INSERT INTO User (id, name, email, password, authProvider, authProviderId, hasDashboardAccess, status, updatedAt) 
                VALUES (:id, :name, :email, :password, :authProvider, :authProviderId, :hasDashboardAccess, :status, CURRENT_TIMESTAMP(3))'
            );
            $stmt->execute([
                ':id' => $userId,
                ':name' => $data['name'],
                ':email' => $data['email'],
                ':password' => $hashedPassword,
                ':authProvider' => 'CREDENTIALS', 
                ':authProviderId' => $userId,
                ':hasDashboardAccess' => 1,
                ':status' => 'pending'
            ]);
    
            // ✅ Insert into Account table (for consistency with Google/Apple logins)
            $stmt = $this->conn->prepare(
                'INSERT INTO Account (id, userId, type, provider, providerAccountId, access_token, refresh_token, expires_at, id_token) 
                VALUES (:id, :userId, :type, :provider, :providerAccountId, NULL, NULL, NULL, NULL)'
            );
            $stmt->execute([
                ':id' => $accountId,
                ':userId' => $userId,
                ':type' => 'CREDENTIALS',
                ':provider' => 'credentials',
                ':providerAccountId' => $userId
            ]);
    
            $this->conn->commit();
    
            $response = [
                'success' => true,
                'user' => [
                    'id' => $userId,
                    'name' => $data['name'],
                    'email' => $data['email'],
                    'authProvider' => 'CREDENTIALS',
                    'hasDashboardAccess' => 1
                ]
            ];
    
            $this->sendResponse($response);
        } catch (PDOException $e) {
            $this->conn->rollBack();
            $this->sendError('Database error: ' . $e->getMessage());
        }
    }
}

$controller = new RegisterManualController();
$controller->register();