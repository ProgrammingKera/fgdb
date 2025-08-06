<?php
// Include header
include_once '../includes/header.php';

// Check if user is a librarian
checkUserRole('librarian');

// Process notification operations
$message = '';
$messageType = '';

// Send new notification
if (isset($_POST['send_notification'])) {
    $userIds = $_POST['user_ids'];
    $notificationMsg = trim($_POST['message']);
    
    // Basic validation
    if (empty($userIds) || empty($notificationMsg)) {
        $message = "Please select at least one user and enter a message.";
        $messageType = "danger";
    } else {
        // Start transaction
        $conn->begin_transaction();
        
        try {
            // Count successful notifications
            $successCount = 0;
            
            // Send notification to each selected user
            foreach ($userIds as $userId) {
                if (sendNotification($conn, $userId, $notificationMsg)) {
                    $successCount++;
                }
            }
            
            $conn->commit();
            
            if ($successCount > 0) {
                $message = "Notification sent successfully to {$successCount} users.";
                $messageType = "success";
            } else {
                $message = "No notifications were sent.";
                $messageType = "warning";
            }
        } catch (Exception $e) {
            $conn->rollback();
            $message = "Error sending notifications: " . $e->getMessage();
            $messageType = "danger";
        }
    }
}


// Get all users for notification sending
$users = [];
$userSql = "SELECT id, name, email, role FROM users ORDER BY name";
$userResult = $conn->query($userSql);
if ($userResult) {
    while ($row = $userResult->fetch_assoc()) {
        $users[] = $row;
    }
}
?>

<h1 class="page-title">Notifications</h1>

<?php if (!empty($message)): ?>
    <div class="alert alert-<?php echo $messageType; ?>">
        <?php echo $message; ?>
    </div>
<?php endif; ?>

<div class="dashboard-row">
    <!-- Send Notification -->
    <div class="dashboard-col">
        <div class="card">
            <div class="card-header">
                <h3>Send New Notification</h3>
            </div>
            <div class="card-body">
                <form action="" method="POST">
                    <div class="form-group">
                        <label for="user_ids">Select Recipients <span class="text-danger">*</span></label>
                        <div class="user-selection-container">
                            <div class="selection-options">
                                <a href="#" onclick="selectAllUsers(); return false;">Select All</a> | 
                                <a href="#" onclick="deselectAllUsers(); return false;">Deselect All</a> | 
                                <a href="#" onclick="selectUsersByRole('student'); return false;">All Students</a> | 
                                <a href="#" onclick="selectUsersByRole('faculty'); return false;">All Faculty</a>
                            </div>
                            <select id="user_ids" name="user_ids[]" multiple class="form-control" style="height: 150px;" required>
                                <?php foreach ($users as $user): ?>
                                    <option value="<?php echo $user['id']; ?>" data-role="<?php echo $user['role']; ?>">
                                        <?php echo htmlspecialchars($user['name']); ?> (<?php echo htmlspecialchars($user['email']); ?>) - <?php echo ucfirst($user['role']); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label for="message">Notification Message <span class="text-danger">*</span></label>
                        <textarea id="message" name="message" class="form-control" rows="5" required></textarea>
                    </div>
                    
                    <div class="form-group text-right">
                        <button type="submit" name="send_notification" class="btn btn-primary">
                            <i class="fas fa-paper-plane"></i> Send Notification
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

<script>
// Function to select all users
function selectAllUsers() {
    const select = document.getElementById('user_ids');
    for (let i = 0; i < select.options.length; i++) {
        select.options[i].selected = true;
    }
}

// Function to deselect all users
function deselectAllUsers() {
    const select = document.getElementById('user_ids');
    for (let i = 0; i < select.options.length; i++) {
        select.options[i].selected = false;
    }
}

// Function to select users by role
function selectUsersByRole(role) {
    const select = document.getElementById('user_ids');
    for (let i = 0; i < select.options.length; i++) {
        if (select.options[i].getAttribute('data-role') === role) {
            select.options[i].selected = true;
        } else {
            select.options[i].selected = false;
        }
    }
}
</script>

<style>
.user-selection-container {
    margin-bottom: 15px;
}

.selection-options {
    margin-bottom: 5px;
    font-size: 0.9em;
}
</style>

<?php
// Include footer
include_once '../includes/footer.php';
?>