CREATE TABLE `nvd` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` text NOT NULL,
  `status` text NOT NULL,
  `description` text NOT NULL,
  `reference` text NOT NULL,
  `phase` text NOT NULL,
  `votes` text NOT NULL,
  `comments` text NOT NULL,
  PRIMARY KEY (`id`)
)
