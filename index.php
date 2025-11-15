<?php
// techlift_onepage.php
// Single-file one-page PHP site with user management for TechLift Liberia
// Uses SQLite (data/techlift.db) and PDO. Make sure directory `data` is writable.

session_start();

define('DB_FILE', __DIR__ . '/data/techlift.db');

// Initialize DB if needed
function getPDO(){
    if(!file_exists(dirname(DB_FILE))){
        mkdir(dirname(DB_FILE), 0755, true);
    }
    $needSeed = !file_exists(DB_FILE);
    $pdo = new PDO('sqlite:' . DB_FILE);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    if($needSeed) seedDB($pdo);
    return $pdo;
}

function seedDB($pdo){
    $pdo->exec("CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );");

    // create a default admin account
    $adminPass = password_hash('Admin@123', PASSWORD_DEFAULT);
    $stmt = $pdo->prepare('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)');
    $stmt->execute(['TechLift Admin', 'admin@techliftliberia.org', $adminPass, 'admin']);
}

$pdo = getPDO();

function flash($name, $message = null){
    if($message === null){
        if(!empty($_SESSION['flash'][$name])){
            $m = $_SESSION['flash'][$name];
            unset($_SESSION['flash'][$name]);
            return $m;
        }
        return null;
    }
    $_SESSION['flash'][$name] = $message;
}

function currentUser(){
    if(!empty($_SESSION['user_id'])){
        global $pdo;
        $stmt = $pdo->prepare('SELECT id, name, email, role FROM users WHERE id = ?');
        $stmt->execute([$_SESSION['user_id']]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }
    return null;
}

// Basic CSRF token
if(empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(16));
function check_csrf($token){
    return hash_equals($_SESSION['csrf'] ?? '', $token ?? '');
}

// Handle actions: register, login, logout, admin_manage_users (create/update/delete)
$action = $_REQUEST['action'] ?? '';
if($_SERVER['REQUEST_METHOD'] === 'POST'){
    if($action === 'register'){
        if(!check_csrf($_POST['csrf'] ?? '')){ flash('error', 'Invalid CSRF token'); header('Location: #auth'); exit; }
        $name = trim($_POST['name']);
        $email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);
        $password = $_POST['password'];
        if(!$name || !$email || !$password){ flash('error', 'Please fill all fields'); header('Location: #auth'); exit; }
        $hash = password_hash($password, PASSWORD_DEFAULT);
        try{
            $stmt = $pdo->prepare('INSERT INTO users (name, email, password) VALUES (?, ?, ?)');
            $stmt->execute([$name, $email, $hash]);
            flash('success', 'Registration successful. You can now sign in.');
        }catch(Exception $e){
            flash('error', 'Registration failed: ' . $e->getMessage());
        }
        header('Location: #auth'); exit;
    }

    if($action === 'login'){
        if(!check_csrf($_POST['csrf'] ?? '')){ flash('error', 'Invalid CSRF token'); header('Location: #auth'); exit; }
        $email = $_POST['email'];
        $password = $_POST['password'];
        $stmt = $pdo->prepare('SELECT id, password FROM users WHERE email = ? LIMIT 1');
        $stmt->execute([$email]);
        $u = $stmt->fetch(PDO::FETCH_ASSOC);
        if($u && password_verify($password, $u['password'])){
            $_SESSION['user_id'] = $u['id'];
            flash('success', 'Signed in successfully');
            header('Location: #dashboard'); exit;
        }else{
            flash('error', 'Invalid credentials'); header('Location: #auth'); exit;
        }
    }

    if($action === 'logout'){
        session_unset(); session_destroy(); session_start(); flash('success', 'Logged out'); header('Location: #home'); exit;
    }

    // Admin actions: create user, update user role, delete user
    if($action === 'admin_create_user' || $action === 'admin_update_user' || $action === 'admin_delete_user'){
        $me = currentUser();
        if(!$me || $me['role'] !== 'admin'){ flash('error', 'Admin access required'); header('Location: #dashboard'); exit; }
        if(!check_csrf($_POST['csrf'] ?? '')){ flash('error', 'Invalid CSRF token'); header('Location: #dashboard'); exit; }

        if($action === 'admin_create_user'){
            $name = trim($_POST['name']);
            $email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);
            $password = $_POST['password'] ?: bin2hex(random_bytes(4));
            $role = $_POST['role'] === 'admin' ? 'admin' : 'user';
            $hash = password_hash($password, PASSWORD_DEFAULT);
            try{
                $stmt = $pdo->prepare('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)');
                $stmt->execute([$name, $email, $hash, $role]);
                flash('success', "User created: $email");
            }catch(Exception $e){ flash('error', 'Create failed: ' . $e->getMessage()); }
            header('Location: #dashboard'); exit;
        }

        if($action === 'admin_update_user'){
            $id = (int)$_POST['id'];
            $role = $_POST['role'] === 'admin' ? 'admin' : 'user';
            try{
                $stmt = $pdo->prepare('UPDATE users SET role = ? WHERE id = ?');
                $stmt->execute([$role, $id]);
                flash('success', 'User updated');
            }catch(Exception $e){ flash('error', 'Update failed: ' . $e->getMessage()); }
            header('Location: #dashboard'); exit;
        }

        if($action === 'admin_delete_user'){
            $id = (int)$_POST['id'];
            try{
                $stmt = $pdo->prepare('DELETE FROM users WHERE id = ?');
                $stmt->execute([$id]);
                flash('success', 'User deleted');
            }catch(Exception $e){ flash('error', 'Delete failed: ' . $e->getMessage()); }
            header('Location: #dashboard'); exit;
        }
    }
}

$user = currentUser();

// Fetch users for admin panel
$users = [];
if($user && $user['role'] === 'admin'){
    $stmt = $pdo->query('SELECT id, name, email, role, created_at FROM users ORDER BY id DESC');
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
}

// Simple helper to escape
function e($s){ return htmlspecialchars($s ?? '', ENT_QUOTES); }

?>

<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>TechLift Liberia — One Page</title>
    <style>
        /* Basic responsive styling */
        :root{ --accent:#0b5cff; }
        body{ font-family: Arial, Helvetica, sans-serif; margin:0; color:#222; }
        header{ background:linear-gradient(90deg,#012a4a,#013a63); color:white; padding:28px 16px; }
        .container{ max-width:1100px; margin:0 auto; padding:24px; }
        nav{ display:flex; gap:12px; align-items:center; flex-wrap:wrap; }
        nav a{ color:white; text-decoration:none; padding:8px 12px; border-radius:6px; }
        nav a:hover{ background:rgba(255,255,255,0.08); }
        .hero{ display:flex; gap:20px; align-items:center; justify-content:space-between; }
        .hero h1{ margin:0 0 8px 0; font-size:28px; }
        .menu{ display:flex; gap:8px; }
        section{ padding:40px 0; border-bottom:1px solid #eee; }
        .grid{ display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:16px; }
        .card{ border:1px solid #e6e6e6; padding:12px; border-radius:8px; background:white; }
        .btn{ display:inline-block; padding:8px 12px; border-radius:6px; text-decoration:none; background:var(--accent); color:white; }
        form input, form textarea, form select{ width:100%; padding:8px; margin:6px 0 12px 0; border:1px solid #ccc; border-radius:6px; }
        .notice{ padding:8px 12px; border-radius:6px; margin-bottom:12px; }
        .notice.success{ background:#e6ffed; border:1px solid #9ef0b6; }
        .notice.error{ background:#ffe6e6; border:1px solid #f09e9e; }
        footer{ background:#f6f9ff; padding:18px 0; text-align:center; }
        table{ width:100%; border-collapse:collapse; }
        table th, table td{ padding:8px; border:1px solid #eee; text-align:left; }
        @media(max-width:700px){ .hero{ flex-direction:column; align-items:flex-start } }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <div class="hero">
                <div>
                    <h1>TechLift Liberia</h1>
                    <p>Empowering Liberia through technology training, certifications, and institutional partnerships.</p>
                </div>
                <div class="menu">
                    <nav>
                        <a href="#home">Home</a>
                        <a href="#about">About</a>
                        <a href="#programs">Programs</a>
                        <a href="#trainings">Trainings</a>
                        <a href="#certifications">Certifications</a>
                        <a href="#partners">Partners</a>
                        <a href="#contact">Contact</a>
                        <a href="#auth">Sign In / Register</a>
                        <?php if($user): ?>
                            <a href="#dashboard">Dashboard</a>
                            <form method="post" style="display:inline-block;margin:0;">
                                <input type="hidden" name="action" value="logout">
                                <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
                                <button class="btn" style="background:#ff4d4d;border:none;cursor:pointer;padding:8px 10px;border-radius:6px;">Logout</button>
                            </form>
                        <?php endif; ?>
                    </nav>
                </div>
            </div>
        </div>
    </header>

    <main class="container">
        <?php if($m = flash('success')): ?><div class="notice success"><?= e($m) ?></div><?php endif; ?>
        <?php if($m = flash('error')): ?><div class="notice error"><?= e($m) ?></div><?php endif; ?>

        <section id="home">
            <h2>Welcome to TechLift Liberia</h2>
            <p>We provide hands-on technology training, certify students with industry-recognized credentials, and partner with universities and organizations to scale digital skills across Liberia.</p>
            <div class="grid">
                <div class="card">
                    <h3>Mission</h3>
                    <p>To uplift communities by teaching practical IT skills, building local capacity, and creating job-ready graduates.</p>
                </div>
                <div class="card">
                    <h3>Vision</h3>
                    <p>A Liberia where technology accelerates economic opportunity for all.</p>
                </div>
                <div class="card">
                    <h3>Join Us</h3>
                    <p>Sign up to receive training updates, or partner with us to host certification programs.</p>
                    <a class="btn" href="#auth">Get Started</a>
                </div>
            </div>
        </section>

        <section id="about">
            <h2>About TechLift Liberia</h2>
            <p>TechLift Liberia is a non-profit initiative focused on practical IT training — network engineering (MikroTik), web development, cybersecurity fundamentals, and more. We collaborate with universities, companies, and donors.</p>
        </section>

        <section id="programs">
            <h2>Programs</h2>
            <div class="grid">
                <div class="card"><h4>Full MikroTik Certs</h4><p>Routing, switching, wireless, and network security training for enterprise networks.</p></div>
                <div class="card"><h4>Web App Development</h4><p>HTML, CSS, JavaScript, PHP, and modern frameworks to build full-stack applications.</p></div>
                <div class="card"><h4>Cybersecurity 101</h4><p>Foundations of security, threat modeling, and defensive practices.</p></div>
            </div>
        </section>

        <section id="trainings">
            <h2>Upcoming Trainings</h2>
            <p>We regularly run cohort-based trainings. Contact us to be notified.</p>
        </section>

        <section id="certifications">
            <h2>Certifications</h2>
            <p>In partnership with industry bodies we offer recognized certifications. Example tracks: MikroTik MTCNA → MTCRE, Web Dev Certificate, CyberAware Certificate.</p>
        </section>

        <section id="partners">
            <h2>Partners</h2>
            <p>We partner with universities, private sector employers, and international donors to expand training capacity.</p>
        </section>

        <section id="contact">
            <h2>Contact</h2>
            <p>Email: <a href="mailto:professorhudsonsiahk@gmail.com">professorhudsonsiahk@gmail.com</a></p>
            <p>Address: Monrovia, Liberia</p>
        </section>

        <section id="auth">
            <h2>Sign In / Register</h2>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
                <div class="card">
                    <h3>Sign In</h3>
                    <form method="post">
                        <input type="hidden" name="action" value="login">
                        <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
                        <label>Email</label>
                        <input type="email" name="email" required>
                        <label>Password</label>
                        <input type="password" name="password" required>
                        <button class="btn" type="submit">Sign In</button>
                    </form>
                </div>

                <div class="card">
                    <h3>Register</h3>
                    <form method="post">
                        <input type="hidden" name="action" value="register">
                        <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
                        <label>Full name</label>
                        <input type="text" name="name" required>
                        <label>Email</label>
                        <input type="email" name="email" required>
                        <label>Password</label>
                        <input type="password" name="password" required>
                        <button class="btn" type="submit">Register</button>
                    </form>
                </div>
            </div>
        </section>

        <section id="dashboard">
            <h2>Dashboard</h2>
            <?php if(!$user): ?>
                <div class="card"><p>Please sign in to access the dashboard.</p></div>
            <?php else: ?>
                <div class="card">
                    <h3>Hello, <?= e($user['name']) ?> (<?= e($user['role']) ?>)</h3>
                    <p>Use the dashboard to manage your account or — if you're an admin — manage users.</p>
                </div>

                <?php if($user['role'] === 'admin'): ?>
                    <div class="card">
                        <h3>Admin — Manage Users</h3>
                        <form method="post" style="margin-bottom:12px;">
                            <input type="hidden" name="action" value="admin_create_user">
                            <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
                            <label>Full name</label>
                            <input name="name" required>
                            <label>Email</label>
                            <input name="email" type="email" required>
                            <label>Temporary password (leave blank to auto-generate)</label>
                            <input name="password">
                            <label>Role</label>
                            <select name="role"><option value="user">User</option><option value="admin">Admin</option></select>
                            <button class="btn" type="submit">Create user</button>
                        </form>

                        <h4>Existing users</h4>
                        <table>
                            <thead><tr><th>ID</th><th>Name</th><th>Email</th><th>Role</th><th>Created</th><th>Actions</th></tr></thead>
                            <tbody>
                                <?php foreach($users as $u): ?>
                                    <tr>
                                        <td><?= e($u['id']) ?></td>
                                        <td><?= e($u['name']) ?></td>
                                        <td><?= e($u['email']) ?></td>
                                        <td><?= e($u['role']) ?></td>
                                        <td><?= e($u['created_at']) ?></td>
                                        <td>
                                            <form method="post" style="display:inline-block;">
                                                <input type="hidden" name="action" value="admin_update_user">
                                                <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
                                                <input type="hidden" name="id" value="<?= e($u['id']) ?>">
                                                <select name="role" onchange="this.form.submit()">
                                                    <option value="user" <?= $u['role']==='user'?'selected':'' ?>>User</option>
                                                    <option value="admin" <?= $u['role']==='admin'?'selected':'' ?>>Admin</option>
                                                </select>
                                            </form>
                                            <form method="post" style="display:inline-block;" onsubmit="return confirm('Delete user?');">
                                                <input type="hidden" name="action" value="admin_delete_user">
                                                <input type="hidden" name="csrf" value="<?= e($_SESSION['csrf']) ?>">
                                                <input type="hidden" name="id" value="<?= e($u['id']) ?>">
                                                <button style="background:#ff6b6b;border:none;padding:6px 8px;border-radius:6px;color:white;cursor:pointer;">Delete</button>
                                            </form>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>

            <?php endif; ?>
        </section>

    </main>

    <footer>
        <div class="container">
            <p>&copy; <?= date('Y') ?> TechLift Liberia — Built for community tech education. Email: professorhudsonsiahk@gmail.com</p>
        </div>
    </footer>

</body>
</html>

