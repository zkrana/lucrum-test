<?php
require_once __DIR__ . '/../core/BaseApi.php';
require_once __DIR__ . '/../config/database.php';

class CpaLegalApi extends BaseApi {
    private $conn;
    private $documentsTable = 'DocumentStorage'; // Fetching from DocumentStorage

    public function __construct() {
        $database = new Database();
        $this->conn = $database->getConnection();
    }

    public function handleRequest() {
        $this->cors();

        switch ($_SERVER['REQUEST_METHOD']) {
            case 'GET':
                $this->handleGetDocuments();
                break;
            default:
                $this->sendError('Method not allowed', 405);
        }
    }

    private function handleGetDocuments() {
        try {
            $token = $this->validateAuth();
            $userId = $this->getUserIdFromToken($token);

            // Fetch only CPA and Legal category documents
            $stmt = $this->conn->prepare(
                "SELECT 
                    id, 
                    title, 
                    description, 
                    file_path AS fileUrl, 
                    file_type, 
                    file_size, 
                    category, 
                    uploaded_by, 
                    is_public, 
                    downloads, 
                    created_at
                FROM " . $this->documentsTable . "
                WHERE category IN ('cpa', 'legal')"
            );

            $stmt->execute();
            $documents = $stmt->fetchAll(PDO::FETCH_ASSOC);

            $this->sendResponse($documents);

        } catch (Exception $e) {
            $this->sendError($e->getMessage(), 500);
        }
    }

    private function getUserIdFromToken($token) {
        // Implement token decoding to extract user ID
        return $token; // Placeholder: Replace with actual logic
    }
}

$api = new CpaLegalApi();
$api->handleRequest();
?>