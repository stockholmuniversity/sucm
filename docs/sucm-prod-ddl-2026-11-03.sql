
/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;
/*!50717 SELECT COUNT(*) INTO @rocksdb_has_p_s_session_variables FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = 'performance_schema' AND TABLE_NAME = 'session_variables' */;
/*!50717 SET @rocksdb_get_is_supported = IF (@rocksdb_has_p_s_session_variables, 'SELECT COUNT(*) INTO @rocksdb_is_supported FROM performance_schema.session_variables WHERE VARIABLE_NAME=\'rocksdb_bulk_load\'', 'SELECT 0') */;
/*!50717 PREPARE s FROM @rocksdb_get_is_supported */;
/*!50717 EXECUTE s */;
/*!50717 DEALLOCATE PREPARE s */;
/*!50717 SET @rocksdb_enable_bulk_load = IF (@rocksdb_is_supported, 'SET SESSION rocksdb_bulk_load = 1', 'SET @rocksdb_dummy_bulk_load = 0') */;
/*!50717 PREPARE s FROM @rocksdb_enable_bulk_load */;
/*!50717 EXECUTE s */;
/*!50717 DEALLOCATE PREPARE s */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `acmeaccount` (
  `Account_Id` int(10) unsigned NOT NULL,
  `Eab_Kid` varchar(64) COLLATE utf8_swedish_ci NOT NULL,
  `Hmac_Key_Encrypted` text COLLATE utf8_swedish_ci NOT NULL,
  `Name` varchar(255) COLLATE utf8_swedish_ci NOT NULL,
  `Topdesk_Ticket` varchar(64) COLLATE utf8_swedish_ci NOT NULL,
  `Status` text COLLATE utf8_swedish_ci NOT NULL,
  `Jwk_Json` text COLLATE utf8_swedish_ci,
  `Requested_By` varchar(255) COLLATE utf8_swedish_ci DEFAULT NULL,
  `Create_Date` datetime DEFAULT NULL,
  `Activated_By` varchar(255) COLLATE utf8_swedish_ci DEFAULT NULL,
  `Activated_Date` datetime DEFAULT NULL,
  PRIMARY KEY (`Account_Id`),
  UNIQUE KEY `uq_acmeaccount_eab_kid` (`Eab_Kid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `acmeaccountdomain` (
  `Domain_Id` int(10) unsigned NOT NULL,
  `Account_Id` int(10) unsigned NOT NULL,
  `Domain_Pattern` varchar(255) COLLATE utf8_swedish_ci NOT NULL,
  PRIMARY KEY (`Domain_Id`),
  KEY `Account_Id` (`Account_Id`),
  CONSTRAINT `acmeaccountdomain_ibfk_1` FOREIGN KEY (`Account_Id`) REFERENCES `acmeaccount` (`Account_Id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `acmeauthorization` (
  `Authz_Id` int(10) unsigned NOT NULL,
  `Order_Id` int(10) unsigned NOT NULL,
  `Identifier_Type` varchar(16) COLLATE utf8_swedish_ci NOT NULL,
  `Identifier_Value` varchar(255) COLLATE utf8_swedish_ci NOT NULL,
  `Status` text COLLATE utf8_swedish_ci NOT NULL,
  `Challenge_Token` varchar(64) COLLATE utf8_swedish_ci NOT NULL,
  `Challenge_Status` text COLLATE utf8_swedish_ci NOT NULL,
  `Expires` datetime NOT NULL,
  PRIMARY KEY (`Authz_Id`),
  KEY `Order_Id` (`Order_Id`),
  CONSTRAINT `acmeauthorization_ibfk_1` FOREIGN KEY (`Order_Id`) REFERENCES `acmeorder` (`Order_Id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `acmenonce` (
  `Nonce` varchar(64) COLLATE utf8_swedish_ci NOT NULL,
  `Create_Date` datetime NOT NULL,
  PRIMARY KEY (`Nonce`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `acmeorder` (
  `Order_Id` int(10) unsigned NOT NULL,
  `Account_Id` int(10) unsigned NOT NULL,
  `Status` text COLLATE utf8_swedish_ci NOT NULL,
  `Identifiers` text COLLATE utf8_swedish_ci NOT NULL,
  `Cert_Id` int(10) unsigned DEFAULT NULL,
  `Expires` datetime NOT NULL,
  `Create_Date` datetime NOT NULL,
  `Error` text COLLATE utf8_swedish_ci,
  PRIMARY KEY (`Order_Id`),
  KEY `Account_Id` (`Account_Id`),
  CONSTRAINT `acmeorder_ibfk_1` FOREIGN KEY (`Account_Id`) REFERENCES `acmeaccount` (`Account_Id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `acmerevealtoken` (
  `Token` varchar(64) COLLATE utf8_swedish_ci NOT NULL,
  `Account_Id` int(10) unsigned NOT NULL,
  `Hmac_Key_Encrypted` text COLLATE utf8_swedish_ci NOT NULL,
  `Create_Date` datetime NOT NULL,
  PRIMARY KEY (`Token`),
  KEY `Account_Id` (`Account_Id`),
  CONSTRAINT `acmerevealtoken_ibfk_1` FOREIGN KEY (`Account_Id`) REFERENCES `acmeaccount` (`Account_Id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `activecertificate` (
  `ActiveCertificate_Id` int(10) unsigned NOT NULL,
  `Cert_Id` int(11) NOT NULL,
  `Common_Name` text COLLATE utf8_swedish_ci NOT NULL,
  `Cert_PEM` text COLLATE utf8_swedish_ci NOT NULL,
  `Create_Date` date DEFAULT NULL,
  `Expiry_Date` date DEFAULT NULL,
  `Cert_Id_Harica` text COLLATE utf8_swedish_ci,
  PRIMARY KEY (`ActiveCertificate_Id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `certificate` (
  `Cert_Id` int(10) unsigned NOT NULL,
  `CA_Id` int(11) NOT NULL,
  `Common_Name` text COLLATE utf8_swedish_ci NOT NULL,
  `Subject_Alt` text COLLATE utf8_swedish_ci NOT NULL,
  `Country` text COLLATE utf8_swedish_ci NOT NULL,
  `State` text COLLATE utf8_swedish_ci NOT NULL,
  `City` text COLLATE utf8_swedish_ci NOT NULL,
  `Org` text COLLATE utf8_swedish_ci NOT NULL,
  `Status` text COLLATE utf8_swedish_ci NOT NULL,
  `Type` text COLLATE utf8_swedish_ci NOT NULL,
  `Secret_Path` text COLLATE utf8_swedish_ci,
  `Notify_Group_Id` int(11) DEFAULT NULL,
  `Create_Date` date DEFAULT NULL,
  `Expiry_Date` date DEFAULT NULL,
  `Cert_Id_Harica` text COLLATE utf8_swedish_ci,
  PRIMARY KEY (`Cert_Id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `certificateauthority` (
  `CA_Id` int(10) unsigned NOT NULL,
  `CA_Name` text COLLATE utf8_swedish_ci NOT NULL,
  `Auth_Method` text COLLATE utf8_swedish_ci NOT NULL,
  PRIMARY KEY (`CA_Id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `idcounter` (
  `name` varchar(64) COLLATE utf8_swedish_ci NOT NULL,
  `value` int(10) unsigned NOT NULL,
  PRIMARY KEY (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `notifygroup` (
  `Group_Id` int(10) unsigned NOT NULL,
  `Group_Name` text COLLATE utf8_swedish_ci NOT NULL,
  `Email_CSV` text COLLATE utf8_swedish_ci NOT NULL,
  PRIMARY KEY (`Group_Id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_swedish_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!50112 SET @disable_bulk_load = IF (@is_rocksdb_supported, 'SET SESSION rocksdb_bulk_load = @old_rocksdb_bulk_load', 'SET @dummy_rocksdb_bulk_load = 0') */;
/*!50112 PREPARE s FROM @disable_bulk_load */;
/*!50112 EXECUTE s */;
/*!50112 DEALLOCATE PREPARE s */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

