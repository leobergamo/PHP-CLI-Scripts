#!/usr/bin/php
<?php

declare(strict_types=1);

namespace assets\bin\discrete\ast\modules\scanForAndBlockBadIPs {





	date_default_timezone_set("America/Detroit");
	require_once('/opt/scripts/PHP/assets/bin/discrete/ast/classes/clsUtilities.php');

	use assets\bin\discrete\ast\classes\utilities as astUtil;

	define('HOME_PATH', '/opt/scripts/PHP/assets/bin/discrete/ast/modules');





	// FYI: command line to reset iptables to stock: iptables-save | awk '/^[*]/ { print $1 } /^:[A-Z]+ [^-]/ { print $1 " ACCEPT" ; } /COMMIT/ { print $0; }' | iptables-restore
	// Yes! I know my namespace and filenames are VERY long but I struggle to be succinct! In time they will be reduced...





	// perform runtime check...
	echo "\n* performing runtime check...\n";
	if ( // argument count is more than one (indice 0 is ignored)...
		count($argv) > 2
	) {

		echo "\n- improper amount of arguments given, expecting none or 1 optional; abort!\n";
		echo "\tSyntax: mdlBlockListOfBadIpsTryingToConnectToApacheServer.php ([post-addition command line])...";
		exit(1);
	}

	if ( // config file or helper script is not viable...
		(
			!file_exists('/opt/scripts/PHP/assets/etc/discrete/ast/config.xml') ||
			!is_readable('/opt/scripts/PHP/assets/etc/discrete/ast/config.xml') ||
			filesize('/opt/scripts/PHP/assets/etc/discrete/ast/config.xml') === 0
		) || (
			!file_exists('/opt/scripts/PHP/assets/bin/discrete/ast/modules/mdlExtractIpFromApacheLogRecsContainingString.php') ||
			!is_readable('/opt/scripts/PHP/assets/bin/discrete/ast/modules/mdlExtractIpFromApacheLogRecsContainingString.php') ||
			filesize('/opt/scripts/PHP/assets/bin/discrete/ast/modules/mdlExtractIpFromApacheLogRecsContainingString.php') === 0
		)
	) {
		echo "- unable to load configuration file, it may not exist or is empty; abort!\n";
		exit(1);
	}





	// declare...
	echo "\n* intializing...\n";
	function checkIfBlockingNetfilterExistForIp(string $_strIp): bool
	{
		(string) $_strOutput = shell_exec(
			"/usr/sbin/iptables -S"
		);

		if (
			strstr(
				$_strOutput,
				$_strIp
			)
		) {
			return true;
		} else {
			return false;
		}
	}

	function CreateBlockingNetfilterForIp(string $_strIp): bool
	{
		if (
			(int)shell_exec(
				"/usr/sbin/iptables -A INPUT -s {$_strIp} -j DROP > /dev/null 2>&1;echo $?"
			) === 0
		) {
			if (
				(int)shell_exec(
					"/usr/sbin/service netfilter-persistent save > /dev/null 2>&1;echo $?"
				) === 0
			) {
				return true;
			} else return false;
		} else return false;
	}

	function saveNetfilters(): bool
	{
		if (
			(int)shell_exec(
				"/usr/sbin/service netfilter-persistent save > /dev/null 2>&1;echo $?"
			) === 0
		) {
			return true;
		} else return false;
	}

	$mxdFh = false;
	(array) $strWriteMode           = "";
	(array) $arrOldFileBuffer       = array();
	(array) $arrNewFileBuffer       = array();
	(array) $arrBlockedIPs          = array();
	(array) $arrNewAdditions        = array();
	(array) $arrBadIPs              = array();
	(array) $arrBadIpsFromAccessLog = "";
	(array) $arrBadIpsFromErrorLog  = "";
	(string) $strLineBuffer         = "";
	(object) $objConfig             = null;
	(object) $objPaths              = null;
	(bool)   $boolChangesMade       = false;





	// main
	$objConfig   = new \SimpleXMLElement(
		file_get_contents(
			'/opt/scripts/PHP/assets/etc/discrete/ast/config.xml'
		)
	);
	$objPaths = $objConfig->main->paths;
	astUtil::init('/opt/scripts/PHP/assets/etc/discrete/ast/config.xml');

	echo "\n* scanning Apache logs...\n";
	if (
		(
			$arrBadIpsFromAccessLog = astUtil::scanLogForBadIPs(
				"access"
			)
		) || (
			$arrBadIpsFromErrorLog  = astUtil::scanLogForBadIPs(
				"error"
			)
		)
	) {
		$arrBadIPs = array_merge($arrBadIpsFromAccessLog, $arrBadIpsFromAccessLog);
		echo "+ found " . count($arrBadIPs) . " bad IP(s)...\n";
	} else {
		echo "- no results found in either Apache log; abort!\n";
		exit(1);
	}

	echo "\n* loading Apache IP blacklist...\n";
	if (
		file_exists($objPaths->apache_ip_blacklist->__toString()) &&
		filesize($objPaths->apache_ip_blacklist->__toString()) > 0 &&
		$mxdFh = fopen(
			$objPaths->apache_ip_blacklist->__toString(),
			'r'
		)
	) { // Apache IP blacklist exist, is not empty and can be open for read...

		while (
			!feof(
				$mxdFh
			)
		) {

			$strLineBuffer = fgets($mxdFh);

			if (
				$strLineBuffer &&
				!strstr($strLineBuffer, '#')
			) {

				$arrOldFileBuffer[] = str_replace(
					["\n", "\r"],
					["", ""],
					$strLineBuffer
				);
			}
		}

		echo "+ found " . count($arrOldFileBuffer) . " record(s)...\n";
		$strWriteMode = 'a';
		fclose($mxdFh);
	} else { // can not open IP blacklist for read; abort!

		$strWriteMode = 'w+';
		echo "- unable to load Apache IP blacklist, it may not exist or is empty; abort!\n";
	}





	echo "\n* processing...\n";
	if (
		$mxdFh = fopen(
			$objPaths->apache_ip_blacklist->__toString(),
			$strWriteMode
		)
	) { // can open Apache IP blacklist for write...

		foreach (
			$arrBadIPs as $strBadIP
		) {

			echo "\n\t* is bad IP: '{$strBadIP}' recognized: ";

			if (
				!in_array(
					"Require not ip {$strBadIP}",
					$arrOldFileBuffer
				) && !in_array(
					"Require not ip {$strBadIP}",
					$arrNewAdditions
				)
			) {

				echo "no\n";
				echo "\t\t* adding bad IP to Apache blacklist: " .
					((fwrite($mxdFh, "# added: " . date("Y-m-d H:i:s") . "\nRequire not ip {$strBadIP}\n") !== false) ? "ok\n" : "fail\n");
				echo "\t\t* does blocking netfilter rule exist: ";
				if (!checkIfBlockingNetfilterExistForIp($strBadIP)) {
					echo "no\n";
					echo "\t\t* creating netfilter rule which will block this IP: " .
						((CreateBlockingNetfilterForIp($strBadIP) === true) ? "ok\n" : "fail\n");
				} else echo "yes\n";
				$arrNewAdditions[] = "Require not ip {$strBadIP}";
				$boolChangesMade = true;
			} else {

				echo "yes\n";
				echo "\t\t* does blocking netfilter rule exist: ";
				if (!checkIfBlockingNetfilterExistForIp($strBadIP)) {
					echo "no\n";
					echo "\t\t\t* creating netfilter rule which will block this IP: " .
						((CreateBlockingNetfilterForIp($strBadIP) === true) ? "ok\n" : "fail\n");
				} else echo "yes\n";
			}
		}

		fclose($mxdFh);
	} else { // can not open IP blacklist for write; abort!

		echo "\n- unable to write to Apache IP blacklist; abort!\n";
		exit(1);
	}





	// finish up...
	echo "\n* finishing up...\n\n";
	if (
		$boolChangesMade
	) {

		echo "\t* " . count($arrNewAdditions) . " bad IP(s) added to Apache IP blacklist and relative netfilter rules established...\n";
		/*
				echo "* restarting Apache server: " .
					(((int)shell_exec('/usr/bin/systemctl restart apache2 > /dev/null 2>&1; echo $?') === 0) ? "ok\n" : "fail\n");
				*/
		echo "\t* saving netfilter rules: " .
			((saveNetfilters() === true) ? "ok\n" : "fail\n");
		echo "\t+ note: Apache IP blacklist can be found at '{$objPaths->apache_ip_blacklist->__toString()}'...\n";
		echo "\t+ tip: Manually restart or create crontab entry to restart Apache server service during off peak times to implement Apache IP blacklist...\n";
		if (count($argv) === 2) {
			echo "\t* executing optional post-addition command line: '{$argv[1]}'...\n";
			shell_exec("/usr/bin/bash -c '{$argv[1]}'");
		} else echo "\t* executing optional post-addition command line: [ not specified ]...\n";
		echo "\t* setting ownership of Apache blacklist: " .
			(((int)shell_exec('/usr/bin/chown www-data:www-data /etc/apache_ip_blacklist > /dev/null 2>&1; echo $?') === 0) ? "ok\n" : "fail\n");
		echo "\t* setting permissions of Apache blacklist: " .
			(((int)shell_exec('/usr/bin/chmod 775 /etc/apache_ip_blacklist > /dev/null 2>&1; echo $?') == 0) ? "ok\n" : "fail\n");
		echo "\n* done...\n\n";
		exit(0);
	} else {

		echo "\t* no new bad IPs found...\n";
		echo "\t+ note: Apache IP blacklist can be found at '{$objPaths->apache_ip_blacklist->__toString()}'...\n";
		echo "\t+ tip: Manually restart or create crontab entry to restart Apache server service during off peak times to implement Apache IP blacklist...\n";
		echo "\n* done...\n\n";
		exit(0);
	}
}
