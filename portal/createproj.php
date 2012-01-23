<?php
// destroy previous session
session_start();
session_regenerate_id();

require 'incs/connect.php';
require 'incs/define.php';
require 'incs/sessman.inc';

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

<!-- <form method="post" action="incs/addproj.php" name="addproj" autocomplete="off"> -->
<form method="post" action="" name="addproj" autocomplete="off">
 <input name="projname"> Project Name<br>
 <input name="custcontact"> Customer Contact Name<br>
 <input name="custphone"> Customer Phone<br>
 <input name="custemail"> Customer Email<br>
<!-- need to add a select assessment types to be performed -->
 <input type="submit" value="Submit Project" name="submit">
</form>

</div>

<div class="logout">
Logged in as: <?php echo $_SESSION['username'] ?> | <a href="incs/logout.php">logout</a> 
</div>

<?php require 'incs/menu.inc' ?>

</body>
</html>