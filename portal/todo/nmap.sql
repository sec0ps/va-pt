SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0;
SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0;
SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='TRADITIONAL';

CREATE SCHEMA IF NOT EXISTS `nmap` DEFAULT CHARACTER SET utf8 ;
USE `nmap` ;

-- -----------------------------------------------------
-- Table `nmap`.`MachineInformation`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `nmap`.`MachineInformation` ;

CREATE  TABLE IF NOT EXISTS `nmap`.`MachineInformation` (
  `machine_id` INT NOT NULL AUTO_INCREMENT ,
  `ip_address` VARCHAR(16) NOT NULL ,
  `mac_address` VARCHAR(20) NOT NULL ,
  `closed_ports_count` INT(11)  NOT NULL ,
  PRIMARY KEY (`machine_id`, `ip_address`) )
ENGINE = InnoDB;
-- COMMENT = 'This contains the basic information about the machine.';


-- -----------------------------------------------------
-- Table `nmap`.`OpenPorts`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `nmap`.`OpenPorts` ;

CREATE  TABLE IF NOT EXISTS `nmap`.`OpenPorts` (
  `id` INT NOT NULL AUTO_INCREMENT ,
  `port_number` INT(11)  NOT NULL ,
  `protocol` VARCHAR(10) NOT NULL ,
  `port_state` VARCHAR(45) NOT NULL ,
  `port_reason` VARCHAR(45) NOT NULL ,
  `port_reason_ttl` INT(11)  NOT NULL ,
  `service_name` VARCHAR(45) NULL ,
  `product` VARCHAR(45) NULL ,
  `script_output` TEXT NULL ,
  `version` VARCHAR(45) NULL ,
  `extra_info` VARCHAR(45) NOT NULL ,
  `ip_address` VARCHAR(45) NOT NULL ,
  PRIMARY KEY (`id`) ,
  CONSTRAINT `fk_OpenPorts_1`
    FOREIGN KEY (`id` )
    REFERENCES `nmap`.`MachineInformation` (`machine_id` )
    ON DELETE NO ACTION
    ON UPDATE NO ACTION)
ENGINE = InnoDB;
-- COMMENT = 'This table contains all the information about open ports';


-- -----------------------------------------------------
-- Table `nmap`.`OperatingSystem`
-- -----------------------------------------------------
DROP TABLE IF EXISTS `nmap`.`OperatingSystem` ;

CREATE  TABLE IF NOT EXISTS `nmap`.`OperatingSystem` (
  `id` INT NOT NULL AUTO_INCREMENT ,
  `type` VARCHAR(45) NOT NULL ,
  `vendor` VARCHAR(45) NULL ,
  `os_family` VARCHAR(45) NULL ,
  `os_gen` VARCHAR(45) NULL ,
  `accuracy` VARCHAR(45) NOT NULL ,
  `fingerprint` LONGTEXT NULL ,
  `ip_address` VARCHAR(45) NULL ,
  PRIMARY KEY (`id`) ,
  CONSTRAINT `ip_address`
    FOREIGN KEY (`id` )
    REFERENCES `nmap`.`MachineInformation` (`machine_id` )
    ON DELETE CASCADE
    ON UPDATE CASCADE)
ENGINE = InnoDB;
-- COMMENT = 'This table holds information about the Operating System that was discovered during nmap';

CREATE INDEX `ip_address` ON `nmap`.`OperatingSystem` (`id` ASC) ;



SET SQL_MODE=@OLD_SQL_MODE;
SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS;
SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS;
