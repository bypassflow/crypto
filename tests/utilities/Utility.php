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

\define('TEST_ROOT_DIR', \dirname(__DIR__));

/**
 * @internal
 */
final class Utility
{
    public const string TEST_ROOT_DIR = TEST_ROOT_DIR;

    private static ?self $instance = null;

    public static function factory(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    private function __construct()
    {
        if (!\is_dir($temp_dir_path = $this->getTempDirPath())) {
            \mkdir($temp_dir_path, 0775, true);
        }

        \touch($this->getCryptFile()->getPathname());
    }

    public function getTempDirPath(): string
    {
        return \sprintf('%s/var/temp_dir', TEST_ROOT_DIR);
    }

    public function getTestFile(): \SplFileInfo
    {
        return new \SplFileInfo(\sprintf('%s/test_data/HashService/test.text', TEST_ROOT_DIR));
    }

    public function getCryptFile($suffix = ''): \SplFileInfo
    {
        return new \SplFileInfo(\sprintf('%s/encrypt%s.text', $this->getTempDirPath(), $suffix));
    }
}
