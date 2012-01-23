<?php
// destroy previous session
session_start();
session_regenerate_id();
session_destroy();
unset($_SESSION);
session_start();
require 'define.php';

?>

<html>
<head>
<title><?php echo title; ?></title>

<link rel="stylesheet" type="text/css" href="search.css" />

</head>
<body>

        <div class="application">
                <h1><?php echo title; ?></h1>
                <hr />
                <p><?php echo description; ?></p>
                <p></p>
                <hr />
                <p class="ms"><strong><?php echo hostname; ?></strong> <?php echo $_SERVER['HTTP_HOST']; ?></p>
                <p class="ms"><strong><?php echo run_date; ?></strong> <?php echo date("Y-m-d H:i:s"); ?></p>
        </div>

        <div class="application">
                <form action="result.php" method="post">
                        <input type="text" name="dbstring" size="25">
                        <input type="submit" value="Search Databases &gt;&gt;" />
                </form>
        </div>

<?php require 'footer.php' ?>

</body>
</html>
