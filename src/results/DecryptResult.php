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

namespace bypassflow\crypt\results;

use bypassflow\crypt\value_objects\CryptConfig;

/**
 * 復号結果
 */
final readonly class DecryptResult
{
    /**
     * factory
     *
     * @param  bool        $outcome     復号が成功したかどうか
     * @param  string      $cipher_text 復号済データ
     * @param  CryptConfig $cryptConfig 複合に必要なデータセット
     * @param  array       $details     詳細
     * @return self        このインスタンス
     */
    public static function of(
        bool $outcome,
        string $text,
        CryptConfig $cryptConfig,
        array $details = [],
    ): self {
        return new self(
            $outcome,
            $text,
            $cryptConfig,
            $details,
        );
    }

    /**
     * constructor
     *
     * @param  bool        $outcome     復号が成功したかどうか
     * @param  string      $cipher_text 復号済データ
     * @param  CryptConfig $cryptConfig 複合に必要なデータセット
     * @param  array       $details     詳細
     * @return self        このインスタンス
     */
    public function __construct(
        public bool $outcome,
        public string $text,
        public CryptConfig $cryptConfig,
        public array $details = [],
    ) {
    }
}
