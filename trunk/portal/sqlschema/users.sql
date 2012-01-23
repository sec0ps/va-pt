CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(40) NOT NULL,
  `password` varchar(40) NOT NULL,
  `email` text NOT NULL,
  `status` int(11) NOT NULL,
  PRIMARY KEY (`id`)
)
