<?php
// This is a separate file on the server (e.g., api_endpoint.php)

// This command runs ONLY when the client-side fetch() function requests this file
exec("/bin/touch /tmp/Robert1.txt");
echo "Command executed on the server.";
?>
