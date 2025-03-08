<?php
require_once '../core/BaseApi.php';
require_once '../config/database.php';

class ProviderLogin extends BaseApi {
    private $db;
    private $conn;

    public function __construct() {
        parent::__construct(); // Call parent constructor to initialize JWT key
        try {
            error_log('Initializing ProviderLogin...');
            $this->db = new Database();
            $this->conn = $this->db->getConnection();
            if (!$this->conn) {
                throw new PDOException("Failed to establish database connection");
            }
            error_log('Database connection established successfully in ProviderLogin');
            $this->cors();
        } catch (PDOException $e) {
            error_log('Database connection error in ProviderLogin: ' . $e->getMessage());
            $this->sendError($e->getMessage(), 500);
        }
    }

    public function login() {
        error_log('Starting provider login process...');
        
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            error_log('Invalid request method: ' . $_SERVER['REQUEST_METHOD']);
            $this->sendError('Method not allowed', 405);
        }

        $data = $this->getRequestBody();
        error_log('Received login data: ' . json_encode($data));

        if (!isset($data['email']) || !isset($data['googleId']) || !isset($data['access_token'])) {
            error_log('Missing required fields in login data');
            $this->sendError('Missing required fields for provider login. Required fields: email, googleId, access_token', 400);
        }

        try {
            // Check if user exists and get user details
            error_log('Checking for user with email: ' . $data['email']);
            $stmt = $this->conn->prepare('SELECT u.*, a.access_token, a.refresh_token, a.expires_at 
                                        FROM User u 
                                        LEFT JOIN Account a ON u.id = a.userId 
                                        WHERE u.email = ? AND u.authProvider = "GOOGLE"');
            $stmt->execute([$data['email']]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if (!$user) {
                error_log('User not found with email: ' . $data['email']);
                $this->sendError('Account not found. Please register first.', 404);
            }

            // Update OAuth tokens
            error_log('Updating OAuth tokens...');
            $stmt = $this->conn->prepare( 
                'UPDATE Account 
                SET access_token = :access_token,
                    refresh_token = :refresh_token,
                    expires_at = :expires_at,
                    id_token = :id_token
                WHERE userId = :userId AND provider = "google"'
            );
            $stmt->execute([
                ':access_token' => $data['access_token'],
                ':refresh_token' => $data['refresh_token'] ?? NULL,
                ':expires_at' => $data['expires_at'] ?? NULL,
                ':id_token' => $data['id_token'] ?? NULL,
                ':userId' => $user['id']
            ]);
            error_log('OAuth tokens updated successfully');

            // Generate JWT token
            error_log('Generating JWT token...');
            $tokenPayload = [
                'id' => $user['id'],
                'email' => $user['email'],
                'name' => $user['name'],
                'status' => $user['status'],
                'hasDashboardAccess' => (bool)$user['hasDashboardAccess']
            ];
            $token = $this->generateJWT($tokenPayload);
            error_log('JWT token generated successfully');

            $response = [
                'success' => true,
                'user' => [
                    'id' => $user['id'],
                    'name' => $user['name'],
                    'email' => $user['email'],
                    'authProvider' => $user['authProvider'],
                    'status' => $user['status'],
                    'hasDashboardAccess' => (bool)$user['hasDashboardAccess']
                ],
                'token' => $token
            ];
            error_log('Sending successful response');
            $this->sendResponse($response);

        } catch (Exception $e) {
            error_log('Error in provider login: ' . $e->getMessage());
            error_log('Error trace: ' . $e->getTraceAsString());
            $this->sendError('Login failed: ' . $e->getMessage(), 500);
        }
    }
}

$api = new ProviderLogin();
$api->login();