<?php
include_once '../includes/config.php';

if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

if (!isset($_SESSION['user_id'])) {
    header('Location: ../index.php');
    exit();
}

if ($_SESSION['role'] != 'student' && $_SESSION['role'] != 'faculty') {
    header('Location: ../index.php');
    exit();
}

$categories = [];
$sql = "
    SELECT 
        category,
        COUNT(*) as book_count
    FROM books
    WHERE category != '' AND category IS NOT NULL
    GROUP BY category 
    ORDER BY category
";
$result = $conn->query($sql);
if ($result) {
    while ($row = $result->fetch_assoc()) {
        $categories[] = $row;
    }
}

$totalBooksQuery = "SELECT COUNT(*) as total FROM books";
$totalBooksResult = $conn->query($totalBooksQuery);
$totalBooks = $totalBooksResult->fetch_assoc()['total'];
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Library Catalog </title>
    <link rel="stylesheet" href="../css/style.css">
    <link rel="icon" type="image/svg+xml" href="../uploads/assests/book.png">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
            color: var(--text-color);
        }
        .catalog-navbar { background: rgba(255, 255, 255, 0.95); backdrop-filter: blur(10px); padding: 15px 0; box-shadow: 0 2px 20px rgba(0, 0, 0, 0.1); position: sticky; top: 0; z-index: 1000; }
        .navbar-container { max-width: 1400px; margin: 0 auto; padding: 0 20px; display: flex; justify-content: space-between; align-items: center; }
        .navbar-brand { display: flex; align-items: center; gap: 12px; text-decoration: none; color: var(--primary-color); }
        .navbar-brand img { height: 65px; width: 100%; }
        .navbar-book_name { font-size: 1.6em; font-weight: bold; }
        .navbar-actions { display: flex; gap: 15px; }
        .nav-btn { padding: 10px 20px; border-radius: 25px; font-weight: 600; text-decoration: none; transition: all 0.3s ease; display: flex; align-items: center; gap: 8px; }
        .dashboard-btn, .logout-btn { color: var(--white); border: none; transition: var(--transition); border-radius: var(--border-radius); }
        .dashboard-btn { background: var(--primary-color); }
        .dashboard-btn:hover { background: var(--primary-light); }
        .logout-btn { background: var(--accent-color); }
        .logout-btn:hover { background: var(--primary-light); }
        .catalog-container { max-width: 1400px; margin: 0 auto; padding: 40px 20px; }
        .welcome-section { text-align: center; margin-bottom: 30px; background: rgba(255, 255, 255, 0.9); padding: 40px; border-radius: 20px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1); }
        .welcome-section h1 { font-size: 3em; margin-bottom: 15px; background: linear-gradient(135deg, var(--primary-color), var(--primary-dark)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .welcome-section p { font-size: 1.2em; color: var(--text-light); margin-bottom: 20px; }
        .toggle-buttons { margin-top: 10px; }
        .toggle-buttons button { padding: 10px 20px; margin: 0 5px; border: none; border-radius: 20px; background-color: #d2b48c; color: #fff; font-weight: bold; cursor: pointer; transition: 0.3s ease; }
        .toggle-buttons button.active { background-color: #a67b5b; }
        .section-content { display: none; }
        .section-content.active { display: block; }
        .library-shelves { background: rgba(255, 255, 255, 0.9); border-radius: 20px; padding: 40px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1); }
        .shelves-header { text-align: center; margin-bottom: 40px; }
        .shelves-header h2 { font-size: 2.5em; color: var(--primary-color); margin-bottom: 10px; }
        .shelves-header p { font-size: 1.1em; color: var(--text-light); }
        .category-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 30px; max-width: 1000px; margin: 0 auto; }
        .category-door { background: linear-gradient(145deg, #8B5E3C, #7C4A2D); border-radius: 15px; height: 200px; border: 3px solid #5A3620; cursor: pointer; overflow: hidden; position: relative; transition: all 0.4s ease; }
        .category-door:hover { transform: perspective(1000px) rotateY(-15deg) scale(1.05); }
        .door-content { display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; color: white; text-align: center; position: relative; z-index: 2; }
        .door-icon { font-size: 3em; margin-bottom: 15px; color: #F9F5F0; text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.3); }
        .door-book_name { font-size: 1.3em; font-weight: 700; margin-bottom: 8px; text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.3); }
        .door-subbook_name { font-size: 0.9em; opacity: 0.9; font-weight: 500; }
        .door-handle { position: absolute; right: 20px; top: 50%; transform: translateY(-50%); width: 12px; height: 12px; background: #C97B4A; border-radius: 50%; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.3); }
    
     }
    .almirah-container {
      padding: 30px 40px;
    }
    .almirah {
      margin-bottom: 50px;
      background-color: #9e7251ff;
      padding: 20px;
      border-radius: 15px;
      border: 2px solid #d4bfa8;
      box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    .almirah h2 {
      text-align: center;
      color: #5c3d26;
      margin-bottom: 20px;
      font-size: 24px;
    }
    .sem-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      justify-items: center;
    }
    .sem-box {
      background-color: #fff;
      border: 1px solid #d9c5b2;
      border-radius: 12px;
      padding: 20px;
      text-align: center;
      width: 100%;
      box-shadow: 0 2px 6px rgba(0,0,0,0.1);
      transition: transform 0.3s;
    }
    .sem-box:hover {
      transform: translateY(-5px);
    }
    .sem-box i {
      font-size: 26px;
      color: #8b5e3c;
      margin-bottom: 10px;
    }
    .sem-box h3 {
      font-size: 18px;
      color: #5c3d26;
      margin-bottom: 5px;
    }
    .sem-box p {
      color: #7c5c44;
      font-size: 14px;

      
    }
    </style>
</head>
<body>
    <nav class="catalog-navbar">
        <div class="navbar-container">
            <a href="#" class="navbar-brand">
                <img src="../uploads/assests/book.png" alt="Library Logo">
                <span class="navbar-book_name">BookBridge</span>
            </a>
            <div class="navbar-actions">
                <a href="dashboard.php" class="nav-btn dashboard-btn"> Dashboard</a>
                <a href="../logout.php" class="nav-btn logout-btn"> Logout</a>
            </div>
        </div>
    </nav>

    <div class="catalog-container">
        <div class="welcome-section">
            <h1>Welcome to Our Book Bridge</h1>
            <p>Discover thousands of books across various categories</p>
            <div class="toggle-buttons">
                <button class="active" onclick="toggleSection('resources')" id="btn-resources">All Resources</button>
                <button onclick="toggleSection('ebooks')" id="btn-ebooks">Ebooks</button>
            </div>
        </div>

        <div id="resources" class="library-shelves section-content active">
            <div class="shelves-header">
                <h2>Browse by Category</h2>
                <p>Click on any door to explore our collection</p>
            </div>
            <div class="category-grid">
                <div class="category-door" onclick="window.location.href='all_books.php'">
                    <div class="door-content">
                        <div class="door-icon"><i class="fas fa-layer-group"></i></div>
                        <div class="door-book_name">All Books</div>
                        <div class="door-subbook_name"><?php echo $totalBooks; ?> books</div>
                    </div>
                    <div class="door-handle"></div>
                </div>
                <?php foreach ($categories as $category): ?>
                <div class="category-door" onclick="window.location.href='category_books.php?category=<?php echo urlencode($category['category']); ?>'">
                    <div class="door-content">
                        <div class="door-icon"><i class="fas fa-book-open"></i></div>
                        <div class="door-book_name"><?php echo htmlspecialchars($category['category']); ?></div>
                        <div class="door-subbook_name"><?php echo $category['book_count']; ?> books</div>
                    </div>
                    <div class="door-handle"></div>
                </div>
                <?php endforeach; ?>
                <div class="category-door" onclick="window.location.href='all_books.php'">
                    <div class="door-content">
                        <div class="door-icon"><i class="fas fa-book-open"></i></div>
                        <div class="door-book_name">Biology</div>
                        <div class="door-subbook_name"><?php echo $totalBooks; ?> books</div>
                    </div>
                    <div class="door-handle"></div>
                </div>
                <div class="category-door" onclick="window.location.href='all_books.php'">
                    <div class="door-content">
                        <div class="door-icon"><i class="fas fa-book-open"></i></div>
                        <div class="door-book_name">Fictions</div>
                        <div class="door-subbook_name"><?php echo $totalBooks; ?> books</div>
                    </div>
                    <div class="door-handle"></div>
                </div>
                <div class="category-door" onclick="window.location.href='all_books.php'">
                    <div class="door-content">
                        <div class="door-icon"><i class="fas fa-book-open"></i></div>
                        <div class="door-book_name">Chemistry</div>
                        <div class="door-subbook_name"><?php echo $totalBooks; ?> books</div>
                    </div>
                    <div class="door-handle"></div>
                </div>
                <div class="category-door" onclick="window.location.href='all_books.php'">
                    <div class="door-content">
                        <div class="door-icon"><i class="fas fa-book-open"></i></div>
                        <div class="door-book_name">History</div>
                        <div class="door-subbook_name"><?php echo $totalBooks; ?> books</div>
                    </div>
                    <div class="door-handle"></div>
                </div>
            </div>
        </div>

        <div id="ebooks" class="library-shelves section-content">
    <div class="shelves-header">
        <h2>Remotely Accessible Ebooks</h2>
        <p>Access ebooks from anywhere at any time</p>
    </div>

    <div class="almirah-container">

        <!-- IT -->
        <div class="almirah">
            <h2 style="color: #ffffffff;">BS Information Technology</h2>
            <div class="sem-grid">
                <div class="sem-box"><i class="fas fa-code"></i><h3>Semester 1</h3><p>45 books</p></div>
                <div class="sem-box"><i class="fas fa-database"></i><h3>Semester 2</h3><p>42 books</p></div>
                <div class="sem-box"><i class="fas fa-network-wired"></i><h3>Semester 3</h3><p>48 books</p></div>
                <div class="sem-box"><i class="fas fa-server"></i><h3>Semester 4</h3><p>51 books</p></div>
                <div class="sem-box"><i class="fas fa-laptop-code"></i><h3>Semester 5</h3><p>39 books</p></div>
                <div class="sem-box"><i class="fas fa-cloud"></i><h3>Semester 6</h3><p>34 books</p></div>
                <div class="sem-box"><i class="fas fa-shield-alt"></i><h3>Semester 7</h3><p>28 books</p></div>
                <div class="sem-box"><i class="fas fa-user-cog"></i><h3>Semester 8</h3><p>24 books</p></div>
            </div>
        </div>

        <!-- HPE -->
        <div class="almirah">
            <h2 style="color: #ffffffff;">BS Health and Physical Education</h2>
            <div class="sem-grid">
                <div class="sem-box"><i class="fas fa-desktop"></i><h3>Semester 1</h3><p>53 books</p></div>
                <div class="sem-box"><i class="fas fa-microchip"></i><h3>Semester 2</h3><p>41 books</p></div>
                <div class="sem-box"><i class="fas fa-robot"></i><h3>Semester 3</h3><p>47 books</p></div>
                <div class="sem-box"><i class="fas fa-cogs"></i><h3>Semester 4</h3><p>36 books</p></div>
                <div class="sem-box"><i class="fas fa-code-branch"></i><h3>Semester 5</h3><p>44 books</p></div>
                <div class="sem-box"><i class="fas fa-terminal"></i><h3>Semester 6</h3><p>40 books</p></div>
                <div class="sem-box"><i class="fas fa-project-diagram"></i><h3>Semester 7</h3><p>33 books</p></div>
                <div class="sem-box"><i class="fas fa-vial"></i><h3>Semester 8</h3><p>22 books</p></div>
            </div>
        </div>

        <!-- ENGLISH -->
        <div class="almirah">
            <h2 style="color: #ffffffff;">BS English</h2>
            <div class="sem-grid">
                <div class="sem-box"><i class="fas fa-pencil-ruler"></i><h3>Semester 1</h3><p>49 books</p></div>
                <div class="sem-box"><i class="fas fa-chart-line"></i><h3>Semester 2</h3><p>38 books</p></div>
                <div class="sem-box"><i class="fas fa-tools"></i><h3>Semester 3</h3><p>43 books</p></div>
                <div class="sem-box"><i class="fas fa-puzzle-piece"></i><h3>Semester 4</h3><p>46 books</p></div>
                <div class="sem-box"><i class="fas fa-stream"></i><h3>Semester 5</h3><p>39 books</p></div>
                <div class="sem-box"><i class="fas fa-cube"></i><h3>Semester 6</h3><p>30 books</p></div>
                <div class="sem-box"><i class="fas fa-clipboard-list"></i><h3>Semester 7</h3><p>26 books</p></div>
                <div class="sem-box"><i class="fas fa-users-cog"></i><h3>Semester 8</h3><p>21 books</p></div>
            </div>
        </div>

        <!-- Intermediate -->
        <div class="almirah">
            <h2 style="color: #ffffffff;">Intermediate</h2>
            <div class="sem-grid">
                <div class="sem-box"><i class="fas fa-book-open"></i><h3>1 year</h3><p>30 books</p></div>
                <div class="sem-box"><i class="fas fa-calculator"></i><h3>2nd year</h3><p>28 books</p></div>
            </div>
        </div>

    </div>
</div>

    </div>

    <script>
        function toggleSection(section) {
            document.getElementById('resources').classList.remove('active');
            document.getElementById('ebooks').classList.remove('active');
            document.getElementById('btn-resources').classList.remove('active');
            document.getElementById('btn-ebooks').classList.remove('active');
            document.getElementById(section).classList.add('active');
            document.getElementById('btn-' + section).classList.add('active');
        }
    </script>
</body>
</html>
