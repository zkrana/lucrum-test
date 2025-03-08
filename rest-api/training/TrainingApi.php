<?php
require_once __DIR__ . '/../core/BaseApi.php';
require_once __DIR__ . '/../config/database.php';

class TrainingApi extends BaseApi {
    private $conn;
    private $progressTable = 'UserTrainingProgress';
    private $videoTable = 'TrainingVideo';
    private $questionTable = 'TrainingQuestion';
    private $userTable = 'User';

    public function __construct() {
        $database = new Database();
        $this->conn = $database->getConnection();
    }

    public function handleRequest() {
        $this->cors();
        
        switch ($_SERVER['REQUEST_METHOD']) {
            case 'GET':
                $this->handleGetProgress();
                break;
            case 'POST':
                $this->handleUpdateProgress();
                break;
            default:
                $this->sendError('Method not allowed', 405);
        }
    }

    private function handleGetProgress() {
        try {
            $token = $this->validateAuth();
            $userId = $this->getUserIdFromToken($token);

            // Fetch training videos with progress
            $stmt = $this->conn->prepare(
                "SELECT v.id as videoId, v.title, v.description, v.videoUrl, v.orderNumber,
                        COALESCE(p.completed, false) as completed,
                        COALESCE(p.questionsCompleted, 0) as questionsCompleted,
                        p.updatedAt
                FROM " . $this->videoTable . " v
                LEFT JOIN " . $this->progressTable . " p
                ON v.id = p.videoId AND p.userId = :userId
                ORDER BY v.orderNumber ASC"
            );
            $stmt->bindParam(':userId', $userId);
            $stmt->execute();
            $progress = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Fetch questions for each video
            foreach ($progress as &$video) {
                $stmt = $this->conn->prepare(
                    "SELECT id, question, answer, options, orderNumber, type
                    FROM " . $this->questionTable . " 
                    WHERE videoId = :videoId 
                    ORDER BY orderNumber ASC"
                );
                $stmt->bindParam(':videoId', $video['videoId']);
                $stmt->execute();
                $video['questions'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
            }

            $this->sendResponse($progress);

        } catch (Exception $e) {
            $this->sendError($e->getMessage(), 500);
        }
    }

    private function handleUpdateProgress() {
        try {
            $token = $this->validateAuth();
            $userId = $this->getUserIdFromToken($token);
            
            $data = $this->getRequestBody();
            if (!isset($data['videoId']) || !isset($data['completed']) || !isset($data['questionsCompleted'])) {
                $this->sendError('Missing required fields', 400);
            }

            $videoId = $data['videoId'];
            $completed = $data['completed'];
            $questionsCompleted = is_bool($data['questionsCompleted']) 
                ? ($data['questionsCompleted'] ? 2 : 0)
                : $data['questionsCompleted'];

            if (!is_bool($completed) || !is_numeric($questionsCompleted) || 
                $questionsCompleted < 0 || $questionsCompleted > 2) {
                $this->sendError('Invalid data format', 400);
            }

            // Verify video exists
            $stmt = $this->conn->prepare(
                "SELECT id FROM " . $this->videoTable . "
                WHERE id = :videoId"
            );
            $stmt->bindParam(':videoId', $videoId);
            $stmt->execute();
            if (!$stmt->fetch()) {
                $this->sendError('Video not found', 404);
            }

            $this->conn->beginTransaction();
            try {
                // Get existing progress
                $stmt = $this->conn->prepare(
                    "SELECT completed, questionsCompleted 
                    FROM " . $this->progressTable . "
                    WHERE userId = :userId AND videoId = :videoId"
                );
                $stmt->bindParam(':userId', $userId);
                $stmt->bindParam(':videoId', $videoId);
                $stmt->execute();
                $existing = $stmt->fetch(PDO::FETCH_ASSOC);

                // Prepare the upsert
                if ($existing) {
                    $finalCompleted = $existing['completed'] || $completed;
                    $finalQuestionsCompleted = max($existing['questionsCompleted'], $questionsCompleted);
                    
                    $stmt = $this->conn->prepare(
                        "UPDATE " . $this->progressTable . "
                        SET completed = :completed, 
                            questionsCompleted = :questionsCompleted,
                            updatedAt = NOW()
                        WHERE userId = :userId AND videoId = :videoId"
                    );
                } else {
                    $finalCompleted = $completed;
                    $finalQuestionsCompleted = $questionsCompleted;
                    
                    $stmt = $this->conn->prepare(
                        "INSERT INTO " . $this->progressTable . " 
                        (id, userId, videoId, completed, questionsCompleted) 
                        VALUES (UUID(), :userId, :videoId, :completed, :questionsCompleted)"
                    );
                }

                $stmt->bindParam(':userId', $userId);
                $stmt->bindParam(':videoId', $videoId);
                $stmt->bindParam(':completed', $finalCompleted, PDO::PARAM_BOOL);
                $stmt->bindParam(':questionsCompleted', $finalQuestionsCompleted);
                $stmt->execute();

                // Check if all videos are completed
                $stmt = $this->conn->prepare(
                    "SELECT COUNT(*) as total FROM " . $this->videoTable
                );
                $stmt->execute();
                $totalVideos = $stmt->fetch(PDO::FETCH_ASSOC)['total'];

                $stmt = $this->conn->prepare(
                    "SELECT COUNT(*) as completed 
                    FROM " . $this->progressTable . "
                    WHERE userId = :userId 
                    AND completed = true 
                    AND questionsCompleted = 2"
                );
                $stmt->bindParam(':userId', $userId);
                $stmt->execute();
                $completedVideos = $stmt->fetch(PDO::FETCH_ASSOC)['completed'];

                $hasDashboardAccess = $completedVideos === $totalVideos;
                if ($hasDashboardAccess) {
                    $stmt = $this->conn->prepare(
                        "UPDATE " . $this->userTable . "
                        SET hasDashboardAccess = true 
                        WHERE id = :userId"
                    );
                    $stmt->bindParam(':userId', $userId);
                    $stmt->execute();
                }

                $this->conn->commit();

                $this->sendResponse([
                    'success' => true,
                    'hasDashboardAccess' => $hasDashboardAccess
                ]);

            } catch (Exception $e) {
                $this->conn->rollBack();
                throw $e;
            }

        } catch (Exception $e) {
            $this->sendError($e->getMessage(), 500);
        }
    }

    private function getUserIdFromToken($token) {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            $this->sendError('Invalid token format', 401);
        }

        try {
            $payload = json_decode(base64_decode(str_replace(['-', '_'], ['+', '/'], $parts[1])), true);
            if (!isset($payload['sub'])) {
                $this->sendError('Invalid token payload', 401);
            }

            if (isset($payload['exp']) && $payload['exp'] < time()) {
                $this->sendError('Token has expired', 401);
            }

            // Verify user exists in database
            $stmt = $this->conn->prepare("SELECT id FROM " . $this->userTable . " WHERE id = ?");
            $stmt->execute([$payload['sub']]);
            if (!$stmt->fetch()) {
                $this->sendError('User not found', 401);
            }

            return $payload['sub'];
        } catch (Exception $e) {
            $this->sendError('Token validation failed: ' . $e->getMessage(), 401);
        }
    }
}

$api = new TrainingApi();
$api->handleRequest();
?>