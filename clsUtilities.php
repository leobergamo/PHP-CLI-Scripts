<?php

declare(strict_types=1);

namespace assets\bin\discrete\ast\classes {
    class utilities
    {

        private static bool    $isInitialized = false;
        private static ?object $objConfig     = null;
        private static ?object $objPaths      = null;
        public static  $intErrorCode          = 0;

        static function init(string $_strConfigPath): bool
        {
            if ( // config file viable...
                file_exists($_strConfigPath) &&
                is_readable($_strConfigPath) &&
                filesize($_strConfigPath)
            ) {
                self::$objConfig = new \SimpleXMLElement(
                    file_get_contents(
                        $_strConfigPath
                    )
                );
                self::$objPaths = self::$objConfig->main->paths;
                self::$isInitialized = true;
                return true;
            } else { // config file not viable...
                self::$isInitialized = false;
                return false;
            }
        }

        static function scanLogForBadIPs(string $_strLogType, string $_strCriteria = "cgi-bin"): array|bool
        {

            if (!self::$isInitialized) {
                self::$intErrorCode = 1;
                return 1;
            }

            $_mxdFh                   = false;
            (string) $_strLineBuffer  = "";
            (array)  $_arrBadIPs      = [];
            (string) $_strLogPath     = (
                ($_strLogType === 'error') ?
                self::$objPaths->apache_error_log->__toString() :
                self::$objPaths->apache_access_log->__toString()
            );
            (int)    $_intResultIndex = (
                ($_strLogType === 'error') ?
                9 :
                0
            );

            if ( // Apache access log file is viable...
                file_exists($_strLogPath) &&
                is_readable($_strLogPath) &&
                filesize($_strLogPath)
            ) {

                if ( // can open Apache access log...
                    $_mxdFh = fopen($_strLogPath, 'r')
                ) {

                    while ( // not end-of-file; keep looping...
                        !feof(
                            $_mxdFh
                        )
                    ) {

                        $_strLineBuffer = fgets($_mxdFh);

                        if ( // line is not empty and contains 'cgi-bin' then record...

                            $_strLineBuffer &&
                            strstr(
                                $_strLineBuffer,
                                $_strCriteria
                            )
                        ) {

                            if ($_strLogType === "error")
                                $_arrBadIPs[] = explode(':', explode(' ', $_strLineBuffer)[$_intResultIndex])[0];

                            if ($_strLogType === "access")
                                $_arrBadIPs[] = explode(' ', $_strLineBuffer)[$_intResultIndex];
                        }
                    }

                    if ( // results...
                        !empty($_arrBadIPs)
                    ) {

                        return $_arrBadIPs;
                    } else { // no results; abort!

                        self::$intErrorCode = 2;
                        return false;
                    }
                } else { // can not open Apache access log; abort!

                    self::$intErrorCode = 3;
                    return false;
                }
            } else { // Apache access log found not viable; abort!

                self::$intErrorCode = 4;
                return false;
            }
        }
    }
}
