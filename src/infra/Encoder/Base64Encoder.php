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

namespace bypassflow\crypt\infra\Encoder;

use bypassflow\crypt\infra\Encoder\interfaces\EncoderInterface;

/**
 * エンコーダーインタフェース
 */
final class Base64Encoder implements EncoderInterface
{
    /**
     * テキストをエンコードします。
     *
     * @param  string $text テキスト
     * @return string エンコードされたテキスト
     */
    public function encode(string $text): string
    {
        return \base64_encode($text);
    }

    /**
     * テキストをデコードします。
     *
     * @param  string $text テキスト
     * @return string デコードされたテキスト
     */
    public function decode(string $text): string
    {
        return \base64_decode($text, true);
    }
}
