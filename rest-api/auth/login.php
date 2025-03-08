<?php
require_once __DIR__ . '/../core/BaseApi.php';
require_once __DIR__ . '/../config/database.php';

class AuthController extends BaseApi {
    private $db;
    private $conn;

    public function __construct() {
        $this->db = new Database();
        $this->conn = $this->db->getConnection();
        $this->cors();
    }

    public function login() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            $this->sendError('Method not allowed', 405);
        }

        $data = $this->getRequestBody();
        
        if (!isset($data['email']) || !isset($data['password'])) {
            $this->sendError('Missing credentials', 400);
        }

        try {
            $stmt = $this->conn->prepare('SELECT id, email, name, password, status, hasDashboardAccess, authProvider, role FROM User WHERE email = ?');
            $stmt->execute([$data['email']]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$user || $user['authProvider'] !== 'CREDENTIALS' || !$user['password']) {
                $this->sendError('Invalid credentials', 401);
            }

            if (!password_verify($data['password'], $user['password'])) {
                $this->sendError('Invalid credentials', 401);
            }

            // Update last_login and updatedAt timestamps
            $updateStmt = $this->conn->prepare('UPDATE User SET last_login = CURRENT_TIMESTAMP(3), updatedAt = CURRENT_TIMESTAMP(3) WHERE id = ?');
            $updateStmt->execute([$user['id']]);

            // Generate JWT token
            $token = $this->generateToken($user['id']);

            $response = [
                'success' => true,
                'user' => [
                    'id' => $user['id'],
                    'email' => $user['email'],
                    'name' => $user['name'],
                    'status' => $user['status'],
                    'role' => $user['role'],
                    'hasDashboardAccess' => (bool)$user['hasDashboardAccess']
                ],
                'token' => $token
            ];

            $this->sendResponse($response);
        } catch (PDOException $e) {
            $this->sendError('Database error: ' . $e->getMessage());
        }
    }

    private function generateToken($userId) {
        $header = json_encode(['typ' => 'JWT', 'alg' => 'HS256']);
        $payload = json_encode([
            'sub' => $userId,
            'iat' => time(),
            'exp' => time() + (30 * 24 * 60 * 60) // 30 days
        ]);

        $base64UrlHeader = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($header));
        $base64UrlPayload = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($payload));

        $signature = hash_hmac('sha256', $base64UrlHeader . '.' . $base64UrlPayload, getenv('NEXTAUTH_SECRET'), true);
        $base64UrlSignature = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($signature));

        return $base64UrlHeader . '.' . $base64UrlPayload . '.' . $base64UrlSignature;
    }
}

$controller = new AuthController();
$controller->login();