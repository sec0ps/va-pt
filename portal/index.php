<?php
// destroy previous session
session_start();
session_regenerate_id();
session_destroy();
unset($_SESSION);
session_start();
require 'incs/define.php';

if ($_SERVER['REMOTE_ADDR'] != '127.0.0.1') {
echo "<meta http-equiv='refresh' content='5; URL=http://www.google.com'>";
echo "Remote connections to this portal are not permitted at this time..redirecting you elsewhere";
exit;
}
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

<?php require 'incs/footer.php' ?>

</body>
</html>
