<?php
$content = file_get_contents("php://input");
$update = json_decode($content, true);

$chat_id = $update["message"]["chat"]["id"];
$message = $update["message"]["text"];

if($message == "/start") {
    sendMessage($chat_id, "Welcome to Stars Gift bot!");
}

function sendMessage($chat_id, $message) {
    $apiToken = "7470843764:AAHObM5mko0JLLxAoWgzANbo7UVYYcZSsuM";
    $url = "https://api.telegram.org/bot$apiToken/sendMessage?chat_id=$chat_id&text=".urlencode($message);
    file_get_contents($url);
}
?>
