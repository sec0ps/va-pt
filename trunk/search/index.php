<?php
	if ($_SERVER['REMOTE_ADDR'] != '127.0.0.1')
	exit( print "Connections to this portal are not permitted from remote systems" );
?>
<?php
// destroy previous session
session_start();
session_regenerate_id();

require 'incs/define.php';
//require 'incs/authorize.php';
//require 'incs/forcessl.inc';
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
 <form action="result.php" method="post">
  <input type="text" name="dbstring" size="25">
  <input type="submit" value="Search Databases &gt;&gt;" />
 </form>
</div>

<?php // require 'incs/menu.inc' ?>

<?php require 'incs/footer.php' ?>

</body>
</html>
