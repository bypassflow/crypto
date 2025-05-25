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

namespace bypassflow\crypt\value_objects;

/**
 * ランダム暗号・複合に必要なデータセット
 */
final readonly class RandomCryptConfig
{
    /**
     * @var int シークレットキーの長さ
     * @static
     */
    public const int DEFAULT_SECRET_KEY_LENGTH  = 5;

    /**
     * factory
     *
     * @param  string $hash_algo         ハッシュあるゴリズム
     * @param  string $salt              ソルト
     * @param  string $hmac_key          HMACキー
     * @param  int    $secret_key_length シークレットキー長
     * @return self   このインスタンス
     */
    public static function of(
        string $hash_algo,
        #[\SensitiveParameter]
        string $salt,
        #[\SensitiveParameter]
        string $hmac_key,
        #[\SensitiveParameter]
        int $secret_key_length = self::DEFAULT_SECRET_KEY_LENGTH,
    ): self {
        return new self(
            $hash_algo,
            $salt,
            $hmac_key,
            $secret_key_length,
        );
    }

    /**
     * constructor
     *
     * @param  string $hash_algo         ハッシュあるゴリズム
     * @param  string $salt              ソルト
     * @param  string $hmac_key          HMACキー
     * @param  int    $secret_key_length シークレットキー長
     * @return self   このインスタンス
     */
    public function __construct(
        string $hash_algo,
        #[\SensitiveParameter]
        string $salt,
        #[\SensitiveParameter]
        string $hmac_key,
        #[\SensitiveParameter]
        int $secret_key_length = self::DEFAULT_SECRET_KEY_LENGTH,
    ) {
    }
}
