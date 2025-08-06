<?php
// Agar root (/) par aaye to register.php serve karo
if ($_SERVER['REQUEST_URI'] === '/' || $_SERVER['REQUEST_URI'] === '/index.php') {
    require 'intro.php'; //  'home.php' jo be karna ho 
    return;
}

// Agar file exist karti hai to usko serve karo
$path = __DIR__ . parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if (is_file($path)) {
    return false; // Let the server handle the request
}


require 'index.php';