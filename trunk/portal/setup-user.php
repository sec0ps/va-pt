<?php
// destroy previous session
session_start();
session_regenerate_id();

require 'incs/define.php';
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

<div class="application">
<form method="post" action="incs/adduser.php" name="adduser" autocomplete="off">
 <input name="username"> Username<br>
 <input name="password" type="password"> Password<br>
 <input name="password1" type="password"> Password<br>
 <input name="email"> Email Address<br>
 <input type="submit" value="Submit User Info" name="submit">
</form>
</div>

</body>
</html>