<?php
require_once __DIR__ . '/../../core/BaseApi.php';
require_once __DIR__ . '/../../config/database.php';

class ProfileApi extends BaseApi {
    private $conn;
    private $table = 'User';

    public function __construct() {
        $database = new Database();
        $this->conn = $database->getConnection();
    }

    public function handleRequest() {
        $this->cors();
        
        switch ($_SERVER['REQUEST_METHOD']) {
            case 'POST':
                $this->handleUpload();
                break;
            case 'GET':
                $this->handleGetImage();
                break;
            default:
                $this->sendError('Method not allowed', 405);
        }
    }

    private function handleUpload() {
        try {
            $token = $this->validateAuth();
            
            if (!isset($_FILES['file'])) {
                $this->sendError('No file uploaded', 400);
            }

            $file = $_FILES['file'];
            
            // Validate file type
            $validMimeTypes = ['image/jpeg', 'image/png', 'image/gif'];
            if (!in_array($file['type'], $validMimeTypes)) {
                $this->sendError('Invalid file type. Only JPEG, PNG, and GIF images are allowed', 400);
            }

            // Validate file size (5MB)
            $maxSize = 5 * 1024 * 1024;
            if ($file['size'] > $maxSize) {
                $this->sendError('File too large. Maximum size is 5MB', 400);
            }

            // Read and validate image content
            $imageData = file_get_contents($file['tmp_name']);
            if (strlen($imageData) < 8) {
                $this->sendError('Invalid image: File too small', 400);
            }

            // Verify image format using magic numbers
            $header = substr($imageData, 0, 4);
            $isJPEG = ord($header[0]) === 0xFF && ord($header[1]) === 0xD8;
            $isPNG = ord($header[0]) === 0x89 && substr($header, 1, 3) === 'PNG';
            $isGIF = substr($header, 0, 3) === 'GIF';

            if (!$isJPEG && !isPNG && !$isGIF) {
                $this->sendError('Invalid image format', 400);
            }

            // Get user ID from token
            $userId = $this->getUserIdFromToken($token);

            // Update user's image in database
            $stmt = $this->conn->prepare(
                "UPDATE " . $this->table . " SET image_data = :image_data WHERE id = :id"
            );

            $stmt->bindParam(':image_data', $imageData, PDO::PARAM_LOB);
            $stmt->bindParam(':id', $userId);

            if ($stmt->execute()) {
                $this->sendResponse(['success' => true]);
            } else {
                $this->sendError('Failed to save image', 500);
            }

        } catch (Exception $e) {
            $this->sendError($e->getMessage(), 500);
        }
    }

    private function handleGetImage() {
        try {
            $token = $this->validateAuth();
            
            $userId = isset($_GET['userId']) ? $_GET['userId'] : null;
            if (!$userId) {
                $this->sendError('User ID is required', 400);
            }

            // Clean up userId
            $userId = explode('?', $userId)[0];
            $userId = explode('&', $userId)[0];

            // Fetch image data
            $stmt = $this->conn->prepare(
                "SELECT image_data FROM " . $this->table . " WHERE id = :id"
            );
            $stmt->bindParam(':id', $userId);
            $stmt->execute();

            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$result || !$result['image_data']) {
                $this->sendError('Image not found', 404);
            }

            $imageData = $result['image_data'];
            
            // Determine content type
            $contentType = 'image/jpeg';
            if (ord($imageData[0]) === 0x89 && substr($imageData, 1, 3) === 'PNG') {
                $contentType = 'image/png';
            } else if (substr($imageData, 0, 3) === 'GIF') {
                $contentType = 'image/gif';
            }

            header('Content-Type: ' . $contentType);
            header('Content-Length: ' . strlen($imageData));
            header('Cache-Control: public, max-age=31536000, immutable');
            echo $imageData;
            exit;

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

$api = new ProfileApi();
$api->handleRequest();
?>