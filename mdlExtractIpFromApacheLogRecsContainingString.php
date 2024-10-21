#!/usr/bin/php
<?php

declare(strict_types=1);

namespace assets\bin\discrete\ast\extractIpFromApacheLogRecsContainingString {

	if ( // argument count is improper or zero...
		count($argv) < 3
	) {

		echo "\nImproper amount or no arguments given; abort!\n";
		echo "\nSyntax: str2ip.php [criteria] [log type]\n";
		echo "----- 'log type' can either be 'access' or 'error'\n\n";
		exit(1);

	}


	if ( // config file found viable...
		file_exists('/opt/scripts/PHP/assets/etc/discrete/ast/config.xml') &&
		is_readable('/opt/scripts/PHP/assets/etc/discrete/ast/config.xml') &&
		filesize('/opt/scripts/PHP/assets/etc/discrete/ast/config.xml')
	) { 

		{ // declare globals...

			$mxdFh                        = false;
			(string) $strLineBuffer       = "";
			(array)  $arrBadIP            = [];
			(object) $objConfigRoot       = new \SimpleXMLElement(file_get_contents('/opt/scripts/PHP/assets/etc/discrete/ast/config.xml'));
			(object) $objConfigChildPaths = $objConfigRoot->main->paths;
			(string) $strLogPath          = (($argv[2] === 'error') ? $objConfigChildPaths->apache_error_log->__toString() : $objConfigChildPaths->apache_access_log->__toString());
			(int)    $intResultIndex      = (($argv[2] === 'error') ? 9 : 0);

		}

		if ( // Apache access log file is viable...
			file_exists($strLogPath) &&
			is_readable($strLogPath) &&
			filesize($strLogPath)
		) {

			if ( // can open Apache access log...
				$mxdFh = fopen($strLogPath, 'r')
			) {

				while ( // not end-of-file; keep looping...
					!feof(
						$mxdFh
					)
				) {

					$strLineBuffer = fgets($mxdFh);

					if ( // line is not empty and contains 'cgi-bin' then record...

						$strLineBuffer &&
						strstr(
							$strLineBuffer,
							$argv[1]
						)
					) {

						if ($argv[2] === "error")
							$arrBadIP[] = explode(':', explode(' ', $strLineBuffer)[$intResultIndex])[0];

						if ($argv[2] === "access")
							$arrBadIP[] = explode(' ', $strLineBuffer)[$intResultIndex];

					}

				}

				if ( // results...
					!empty($arrBadIP)
				) {

					echo json_encode($arrBadIP) . "\n";
					exit(0);

				} else { // no results; abort!

					echo "\nNo results found; abort!\n";
					exit(1);

				}

			} else { // can not open Apache access log; abort!

				echo "\nUnable to access access log; abort!\n";
				exit(1);

			}
		} else { // Apache access log found not viable; abort!

			echo "\nUnable to open Apache log; abort!\n";
			exit(1);
		}

	} else { // config file found not viable; abort!

		echo "Aborting, configuration file is not accessible or empty!\n";
		exit(1);

	}

}
