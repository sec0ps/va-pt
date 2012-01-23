CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(40) NOT NULL,
  `password` varchar(40) NOT NULL,
  `email` text NOT NULL,
  `status` int(11) NOT NULL,
  PRIMARY KEY (`id`)
)

insert into users (username, password, email, status) values ('"vapt","269358d235f932225280eb0e9f77bb9c727eba97","enforce570@gmail.com",'0');
