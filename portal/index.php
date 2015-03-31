<?php
// destroy previous session
session_start();
session_regenerate_id();
session_destroy();
unset($_SESSION);
session_start();
session_regenerate_id();
require 'incs/define.php';
require 'incs/remote.php';
?>

<html>
<head>
<title><?php echo title; ?></title>

<link rel="stylesheet" type="text/css" href="incs/index.css" />

</head>
<body>

<div class="application">
                <h1><?php echo title; ?></h1>
                <hr />
                <p><?php echo description; ?></p>
</div>

<div class="message">
<center>
 <form method="post" action="incs/auth.php" name="auth" autocomplete="off">
 <input name="username" type="username"><br>
 <input name="password" type="password"><br>	
 <input type="submit" value="Login">
 </form>
</center>
</div>
</body>
</html>
