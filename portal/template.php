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

<?php require 'incs/footer.php' ?>

</body>
</html>
