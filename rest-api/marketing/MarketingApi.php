<?php
require_once __DIR__ . '/../core/BaseApi.php';
require_once __DIR__ . '/../config/database.php';

class ContentApi extends BaseApi {
    private $conn;
    private $contentTable = 'Content';

    public function __construct() {
        $database = new Database();
        $this->conn = $database->getConnection();
    }

    public function handleRequest() {
        $this->cors();
        
        switch ($_SERVER['REQUEST_METHOD']) {
            case 'GET':
                $this->handleGetContent();
                break;
            default:
                $this->sendError('Method not allowed', 405);
        }
    }

    private function handleGetContent() {
        try {
            $token = $this->validateAuth();
            $userId = $this->getUserIdFromToken($token);

            $stmt = $this->conn->prepare(
                "SELECT id, title, description, type, file_path, thumbnail_path, 
                        size, mime_type, downloads, views, created_by, 
                        created_at, updated_at, videoType
                FROM " . $this->contentTable . "
                ORDER BY created_at DESC"
            );
            $stmt->execute();

            $content = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $this->sendResponse($content);

        } catch (Exception $e) {
            $this->sendError($e->getMessage(), 500);
        }
    }

    private function getUserIdFromToken($token) {
        // Implement your token validation logic here
        // This is a placeholder - you should properly decode and validate the JWT token
        return $token;
    }
}

// Initialize API
$api = new ContentApi();
$api->handleRequest();
?>