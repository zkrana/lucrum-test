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

class RegisterProvider extends BaseApi {
    private $db;
    private $conn;

    public function __construct() {
        parent::__construct(); // Call parent constructor to initialize JWT key
        try {
            error_log('Initializing RegisterProvider...');
            $this->db = new Database();
            $this->conn = $this->db->getConnection();
            if (!$this->conn) {
                throw new PDOException("Failed to establish database connection");
            }
            error_log('Database connection established successfully in RegisterProvider');
            $this->cors();
        } catch (PDOException $e) {
            error_log('Database connection error in RegisterProvider: ' . $e->getMessage());
            $this->sendError($e->getMessage(), 500);
        }
    }

    public function register() {
        error_log('Starting provider registration process...');
        
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            error_log('Invalid request method: ' . $_SERVER['REQUEST_METHOD']);
            $this->sendError('Method not allowed', 405);
        }

        $data = $this->getRequestBody();
        error_log('Received registration data: ' . json_encode($data));

        if (!isset($data['email']) || !isset($data['googleId']) || !isset($data['access_token'])) {
            error_log('Missing required fields in registration data');
            $this->sendError('Missing required fields for provider signup. Required fields: email, googleId, access_token', 400);
        }

        try {
            // Check if user exists by email
            error_log('Checking for existing user with email: ' . $data['email']);
            $stmt = $this->conn->prepare('SELECT id, authProvider FROM User WHERE email = ?');
            $stmt->execute([$data['email']]);
            $existingUser = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($existingUser) {

                error_log('User already exists with email: ' . $data['email']);
                
                if ($existingUser['authProvider'] === 'GOOGLE') {
                    $this->sendError('Account already exists with Google login', 400);

                } else {
                    $this->sendError('Account already exists with a different login method', 400);
                }
            }

            error_log('Beginning database transaction...');
            $this->conn->beginTransaction();

            // Generate UUIDs
            $userId = generateUUID();
            $authProviderId = generateUUID();
            error_log('Generated UUIDs - userId: ' . $userId . ', authProviderId: ' . $authProviderId);

            // Insert user
            error_log('Inserting new user record...');
            $stmt = $this->conn->prepare(
                'INSERT INTO User (id, name, email, authProvider, authProviderId, hasDashboardAccess, status, updatedAt, createdAt) 
                VALUES (:id, :name, :email, :authProvider, :authProviderId, :hasDashboardAccess, :status, CURRENT_TIMESTAMP(3), CURRENT_TIMESTAMP(3))'
            );
            $stmt->execute([
                ':id' => $userId,
                ':name' => $data['name'],
                ':email' => $data['email'],
                ':authProvider' => 'GOOGLE',
                ':authProviderId' => $authProviderId,
                ':hasDashboardAccess' => 1,
                ':status' => 'active'
            ]);
            error_log('User record inserted successfully');

            // Insert Google OAuth tokens
            error_log('Inserting OAuth account record...');
            $accountId = generateUUID();
            $stmt = $this->conn->prepare(
                'INSERT INTO Account (id, userId, type, provider, providerAccountId, access_token, refresh_token, expires_at, id_token, token_type, scope, session_state) 
                VALUES (:id, :userId, :type, :provider, :providerAccountId, :access_token, :refresh_token, :expires_at, :id_token, :token_type, :scope, :session_state)'
            );
            $stmt->execute([
                ':id' => $accountId,
                ':userId' => $userId,
                ':type' => 'oauth',
                ':provider' => 'google',
                ':providerAccountId' => $data['googleId'],
                ':access_token' => $data['access_token'],
                ':refresh_token' => $data['refresh_token'] ?? NULL,
                ':expires_at' => $data['expires_at'] ?? NULL,
                ':id_token' => $data['id_token'] ?? NULL,
                ':token_type' => 'Bearer',
                ':scope' => 'openid profile email',
                ':session_state' => NULL
            ]);
            error_log('OAuth account record inserted successfully');

            error_log('Committing transaction...');
            $this->conn->commit();
            error_log('Transaction committed successfully');

            // Generate JWT token
            error_log('Generating JWT token...');
            $tokenPayload = [
                'id' => $userId,
                'email' => $data['email'],
                'name' => $data['name'],
                'status' => 'active',
                'hasDashboardAccess' => true
            ];
            $token = $this->generateJWT($tokenPayload);
            error_log('JWT token generated successfully');

            $response = [
                'success' => true,
                'user' => [
                    'id' => $userId,
                    'name' => $data['name'],
                    'email' => $data['email'],
                    'authProvider' => 'GOOGLE',
                    'status' => 'active',
                    'hasDashboardAccess' => true
                ],
                'token' => $token
            ];
            error_log('Sending successful response');
            $this->sendResponse($response);

        } catch (Exception $e) {
            error_log('Error in provider registration: ' . $e->getMessage());
            error_log('Error trace: ' . $e->getTraceAsString());
            
            if ($this->conn->inTransaction()) {
                error_log('Rolling back transaction...');
                $this->conn->rollBack();
            }
            
            $this->sendError('Registration failed: ' . $e->getMessage(), 500);
        }
    }
}

$api = new RegisterProvider();
$api->register();