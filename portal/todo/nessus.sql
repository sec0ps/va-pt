SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='TRADITIONAL';

DROP SCHEMA IF EXISTS `nessus` ;
CREATE SCHEMA IF NOT EXISTS `nessus` DEFAULT CHARACTER SET utf8 ;
USE `nessus` ;

-- -----------------------------------------------------
-- Table `nessus`.`HostProperties`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `nessus`.`HostProperties` ;

CREATE  TABLE IF NOT EXISTS `nessus`.`HostProperties` (
  `host_id` INT NOT NULL AUTO_INCREMENT ,
  `host_ip` VARCHAR(20) NOT NULL ,
  `operating_system` VARCHAR(80) NOT NULL ,
  PRIMARY KEY (`host_id`, `host_ip`) )
ENGINE = InnoDB;


-- -----------------------------------------------------
-- Table `nessus`.`Ports`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `nessus`.`Ports` ;

CREATE  TABLE IF NOT EXISTS `nessus`.`Ports` (
  `idPorts` INT NOT NULL ,
  `port_number` INT(11)  NOT NULL ,
  `service_name` VARCHAR(80) NULL ,
  `protocol` VARCHAR(45) NOT NULL ,
  `severity` INT(11)  NULL ,
  `solution` LONGTEXT NULL ,
  `risk_factor` VARCHAR(45) NULL ,
  `description` TEXT NULL ,
  `synopsis` TEXT NULL ,
  `see_also` TEXT NULL ,
  `plugin_output` LONGTEXT NULL ,
  `port_id` INT(11)  NOT NULL AUTO_INCREMENT ,
  INDEX `fk_Ports_1` (`idPorts` ASC) ,
  PRIMARY KEY (`port_id`) ,
  CONSTRAINT `fk_Ports_1`
    FOREIGN KEY (`idPorts` )
    REFERENCES `nessus`.`HostProperties` (`host_id` )
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;



SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;
