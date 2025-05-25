<?php
/**
 *    ___                        _____
 *   / _ )__ _____ ___ ____ ___ / _/ ___ _    __
 *  / _  / // / _ / _ `(_-<(_-</ _/ / _ | |/|/ /
 * /____/\_, / .__\_,_____/___/_//_/\___|__,__/
 *  __________/_____ / /_
 * / __/ __/ // / _ / __/
 * \__/_/  \_, / .__\__/
 *        /___/_/
 *
 * @package     bypassflow
 * @category    crypt
 * @author      wakaba <wakabadou@gmail.com>
 * @copyright   Copyright (c) @2025  Wakabadou (http://www.wakabadou.net/) / Project ICKX (https://ickx.jp/). All rights reserved.
 * @license     http://opensource.org/licenses/MIT The MIT License.
 *              This software is released under the MIT License.
 */

declare(strict_types=1);

namespace bypassflow\crypt\tests\utilities;

/**
 * @internal
 */
abstract class AbstractTestCase extends \PHPUnit\Framework\TestCase
{
    public function setUp(): void
    {
        \set_error_handler(function($errno, $errstr, $errfile, $errline): void {
            throw new \RuntimeException(\sprintf('Error #%s: %s on %s(%s)', $errno, $errstr, $errfile, $errline));
        });
    }

    public function tearDown(): void
    {
        \restore_error_handler();
    }
}
