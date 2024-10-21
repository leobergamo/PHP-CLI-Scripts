#!/usr/bin/php
<?php

declare(strict_types=1);

namespace assets\bin\discrete\ast\modules\blockListOfBadIpsTryingToConnectToApacheServer {

	// fyi: command line to reset iptables to stock: iptables-save | awk '/^[*]/ { print $1 } /^:[A-Z]+ [^-]/ { print $1 " ACCEPT" ; } /COMMIT/ { print $0; }' | iptables-restore

	// perform runtime check...
	if ( // argument count is improper or zero...
		count($argv) > 2
	) {

		echo "\n- improper amount of arguments given, expecting none or optional; abort!\n";
		echo "\tSyntax: updateBlacklist.php ([post-addition command line])...";
		exit(1);
	}

	if ( // config file and mdlGetIpFromApacheLogRecsContaining.php script viable...
		(
			file_exists('/opt/scripts/PHP/assets/etc/discrete/ast/config.xml') &&
			is_readable('/opt/scripts/PHP/assets/etc/discrete/ast/config.xml') &&
			filesize('/opt/scripts/PHP/assets/etc/discrete/ast/config.xml')
		) && (
			file_exists('/opt/scripts/PHP/assets/etc/discrete/ast/config.xml') &&
			is_readable('/opt/scripts/PHP/assets/etc/discrete/ast/config.xml') &&
			filesize('/opt/scripts/PHP/assets/etc/discrete/ast/config.xml')
		)
	) {
		// declare globals...

		function checkIfBlockedUsingNetfilter(string $_strIp): bool
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


		function blockIpUsingNetfilter(string $_strIp): bool
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
		(array) $arrOldFileBuffer = array();
		(array) $arrNewFileBuffer = array();
		(array) $arrBlockedIPs = array();

		try {

			echo "\n\n* generating list of bad IPs from Apache error and access logs...";
			(array) $arrBadIPs   = array_merge(
				json_decode(
					shell_exec(
						"/opt/scripts/PHP/assets/bin/discrete/ast/modules/mdlExtractIpFromApacheLogRecsContainingString.php cgi-bin access"
					),
					true
				),
				json_decode(
					shell_exec(
						"/opt/scripts/PHP/assets/bin/discrete/ast/modules/mdlExtractIpFromApacheLogRecsContainingString.php cgi-bin error"
					),
					true
				)
			);
		} catch (\Exception $objEx) {

			echo "- Failed to generate list; abort!";
			exit(1);
		}

		(string) $strLineBuffer   = "";
		(object) $objConfigRoot   = new \SimpleXMLElement(
			file_get_contents(
				'/opt/scripts/PHP/assets/etc/discrete/ast/config.xml'
			)
		);
		(object) $objConfigPaths = $objConfigRoot->main->paths;
		(bool)   $boolChangesMade = false;

		if (
			$mxdFh = fopen(
				$objConfigPaths->apache_ip_blacklist->__toString(),
				'a+'
			)
		) { // can open IP blacklist...

			echo "\n\n* generating list from Apache IP blacklist of known bad IPs...";
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

			echo "\n\n* comparing items on former to the latter...\n";
			foreach (
				$arrBadIPs as $strBadIP
			) {

				echo "\n\t* is bad IP: '{$strBadIP}' recognized:  ";

				if (
					!empty($arrOldFileBuffer)
				) {

					if (
						!in_array(
							"Require not ip {$strBadIP}",
							$arrOldFileBuffer
						)
					) {

						echo "no\n";
						echo "\t\t* does netfilter rule exist: ";
						if (!checkIfBlockedUsingNetfilter($strBadIP)) {
							echo "no\n";
							echo "\t\t* creating netfilter rule which will block this IP: " .
								((blockIpUsingNetfilter($strBadIP) === true) ? "ok\n" : "fail\n");
						} else echo "yes\n";
						echo "\t\t* adding this IP to Apache blacklist: " .
							((fwrite($mxdFh, "Require not ip {$strBadIP}\n") !== false) ? "ok\n" : "fail\n");
						$boolChangesMade = true;
					} else {

						echo "yes\n";
						echo "\t\t* does netfilter rule exist: ";
						if (!checkIfBlockedUsingNetfilter($strBadIP)) {
							echo "no\n";
							echo "\t\t* creating netfilter rule which will block this IP: " .
								((blockIpUsingNetfilter($strBadIP) === true) ? "ok\n" : "fail\n");
						} else echo "yes\n";
					}
				} else {

					echo "no\n";
					echo "\t\t* does netfilter rule exist: ";
					if (!checkIfBlockedUsingNetfilter($strBadIP)) {
						echo "no\n";
						echo "\t\t* creating netfilter rule which will block this IP: " .
							((blockIpUsingNetfilter($strBadIP) === true) ? "ok\n" : "fail\n");
					} else echo "yes\n";
					echo "\t\t* adding this IP to Apache blacklist: " .
						((fwrite($mxdFh, "Require not ip {$strBadIP}\n") !== false) ? "ok\n" : "fail\n");
					$boolChangesMade = true;
				}
			}

			fclose($mxdFh);

			if (
				$boolChangesMade
			) {

				echo "\n\n* bad IP(s) added to Apache IP blacklist and relative netfilter rules established...\n";
				/*
				echo "* restarting Apache server: " .
					(((int)shell_exec('/usr/bin/systemctl restart apache2 > /dev/null 2>&1; echo $?') === 0) ? "ok\n" : "fail\n");
				*/
				echo "* saving netfilter rules: " .
					((saveNetfilters() === true) ? "ok\n" : "fail\n");
				echo "* note: Apache IP blacklist can be found at '{$objConfigPaths->apache_ip_blacklist->__toString()}'...\n";
				echo "* tip: Manually restart or create crontab entry to restart Apache server service during off peak times to implement Apache IP blacklist...\n";
				if (count($argv) === 2) {
					echo "* executing optional post-addition command line: '{$argv[1]}'...\n\n";
					echo "----------COMMAND OUTPUT---------\n";
					echo shell_exec("/usr/bin/bash -c '{$argv[1]}'");
					echo "---------------------------------\n\n";
				} else echo "* executing optional post-addition command line: [ not specified ]...\n";
				echo "* setting ownership of Apache blacklist: " .
					(((int)shell_exec('/usr/bin/chown www-data:www-data /etc/apache_ip_blacklist > /dev/null 2>&1; echo $?') === 0) ? "ok\n" : "fail\n");
				echo "* setting permissions of Apache blacklist: " .
					(((int)shell_exec('/usr/bin/chmod 775 /etc/apache_ip_blacklist > /dev/null 2>&1; echo $?') == 0) ? "ok\n" : "fail\n");
				echo "* done...\n\n";
				exit(0);
			} else {

				echo "\n\n* no new bad IPs found...\n";
				echo "* note: Apache IP blacklist can be found at '{$objConfigPaths->apache_ip_blacklist->__toString()}'...\n";
				echo "* tip: Manually restart or create crontab entry to restart Apache server service during off peak times to implement Apache IP blacklist...\n";
				echo "* done...\n\n";
				exit(0);
			}
		} else { // can not open IP blacklist; abort!


			echo "\n- unable to access IP blacklist; abort!\n";
			exit(1);
		}

	} else { //  config file and or mdlGetIpFromApacheLogRecsContaining.php script not viable; abort!

		echo "- configuration file and or helper script not viable; abort!\n";
		exit(1);

	}

}
