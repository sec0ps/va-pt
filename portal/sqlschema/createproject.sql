CREATE TABLE `application`.`projects` (
  `id` INT(11)  NOT NULL AUTO_INCREMENT,
  `projname` TEXT(50)  NOT NULL,
  `custcontact` TEXT(50)  NOT NULL,
  `custphone` TEXT(50)  NOT NULL,
  `custemail` TEXT(50)  NOT NULL,
  PRIMARY KEY (`id`)
);