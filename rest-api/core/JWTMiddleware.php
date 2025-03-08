<?php
require_once __DIR__ . '/../vendor/autoload.php';
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class JWTMiddleware {
    private static function getToken() {
        $headers = getallheaders();
        $authHeader = isset($headers['Authorization']) ? $headers['Authorization'] : '';
        
        if (empty($authHeader) || !preg_match('/Bearer\s+(\S+)/', $authHeader, $matches)) {
            return null;
        }
        
        return $matches[1];
    }

    public static function validateToken() {
        $token = self::getToken();
        if (!$token) {
            header('Content-Type: application/json');
            http_response_code(401);
            echo json_encode(['error' => true, 'message' => 'Unauthorized']);
            exit;
        }

        try {
            $key = getenv('NEXTAUTH_SECRET');
            if (!$key) {
                throw new Exception('JWT secret key not configured');
            }

            $decoded = JWT::decode($token, new Key($key, 'HS256'));
            $payload = (array) $decoded;

            // Check expiration
            if (!isset($payload['exp']) || $payload['exp'] < time()) {
                header('Content-Type: application/json');
                http_response_code(401);
                echo json_encode(['error' => true, 'message' => 'Token expired']);
                exit;
            }

            return $payload;
        } catch (Exception $e) {
            header('Content-Type: application/json');
            http_response_code(401);
            echo json_encode(['error' => true, 'message' => 'Invalid token']);
            exit;
        }
    }
}