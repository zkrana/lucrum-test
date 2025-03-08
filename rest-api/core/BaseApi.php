<?php
require_once __DIR__ . '/../../../vendor/autoload.php';
use Firebase\JWT\JWT;

class BaseApi {
    private $jwtKey;
    private $jwtAlgorithm = 'HS256';

    public function __construct() {
        $keyPath = __DIR__ . '/../../../config/.key';
        if (!file_exists($keyPath)) {
            throw new Exception('JWT secret key file not found');
        }
        $this->jwtKey = trim(file_get_contents($keyPath));
        if (empty($this->jwtKey)) {
            throw new Exception('JWT secret key is empty');
        }
    }

    protected function generateJWT($payload) {
        $issuedAt = time();
        $expirationTime = $issuedAt + 24 * 60 * 60; // 24 hours from now

        $tokenPayload = array_merge(
            $payload,
            [
                'iat' => $issuedAt,
                'exp' => $expirationTime
            ]
        );

        return JWT::encode($tokenPayload, $this->jwtKey, $this->jwtAlgorithm);
    }

    protected function sendResponse($data, $statusCode = 200) {
        header('Content-Type: application/json');
        http_response_code($statusCode);
        echo json_encode($data);
        exit;
    }

    protected function sendError($message, $statusCode = 500) {
        $response = [
            'error' => true,
            'message' => $message
        ];
        $this->sendResponse($response, $statusCode);
    }

    protected function getRequestBody() {
        return json_decode(file_get_contents('php://input'), true);
    }

    protected function validateAuth() {
        $headers = getallheaders();
        $authHeader = isset($headers['Authorization']) ? $headers['Authorization'] : '';
        
        if (empty($authHeader) || !preg_match('/Bearer\s+(\S+)/', $authHeader, $matches)) {
            $this->sendError('Unauthorized', 401);
        }
        
        return $matches[1]; // Return the token for further validation
    }

    protected function cors() {
        if (php_sapi_name() === 'cli') return;
        
        // Prevent any output before headers
        if (headers_sent()) {
            throw new Exception('Headers already sent');
        }

        // Allow credentials and set specific origins
        header('Access-Control-Allow-Credentials: true');
        header('Access-Control-Allow-Origin: ' . (isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : '*'));
        header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
        header('Content-Type: application/json');
        
        if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
            http_response_code(200);
            exit(0);
        }
    }
}
?>