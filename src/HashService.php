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

namespace bypassflow\crypt;

/**
 * ハッシュサービス
 */
final class HashService
{
    /**
     * @var string デフォルトのハッシュアルゴリズム
     */
    public const DEFAULT_HASH_ALOG  = 'sha256';

    /**
     * @var int シークレットキーの長さ
     * @static
     */
    public const SECRET_KEY_LENGTH	 = 5;

    /**
     * @var array HMACで使用出来ないハッシュアルゴリズム
     * @static
     */
    public const array NOT_USE_HMAC_ALGOS   = ['adler32', 'crc32', 'crc32b', 'fnv132', 'fnv1a32', 'fnv164', 'fnv1a64', 'joaat'];

    /**
     * @var bool HMACで使用できないハッシュアルゴリズムが指定されているかどうか
     */
    public readonly bool $not_use_hmac_algo;

    /**
     * @var \Random\Randomizer ランダマイザ
     */
    private readonly \Random\Randomizer $randomizer;

    /**
     * factory
     *
     * @param  string                  $hash_alog  ハッシュあるゴリズム
     * @param  null|\Random\Randomizer $randomizer ランダマイザ
     * @return self                    このインスタンス
     */
    public static function factory(
        string $hash_alog = self::DEFAULT_HASH_ALOG,
        ?\Random\Randomizer $randomizer = null,
    ): self {
        return new self(
            $hash_alog,
            $randomizer,
        );
    }

    /**
     * constructor
     *
     * @param string                  $hash_alog  ハッシュあるゴリズム
     * @param null|\Random\Randomizer $randomizer ランダマイザ
     */
    public function __construct(
        private readonly string $hash_alog,
        ?\Random\Randomizer $randomizer = null,
    ) {
        $this->randomizer           = $randomizer ?? new \Random\Randomizer();
        $this->not_use_hmac_algo    = \in_array($hash_alog, self::NOT_USE_HMAC_ALGOS, true);
    }

    /**
     * 文字列を元にハッシュ文字列を生成します。
     *
     * @param  string $data 文字列
     * @return string ハッシュ文字列
     */
    public function string(string $data): string
    {
        return \hash($this->hash_alog, $data, false);
    }

    /**
     * 文字列を元にハッシュバイナリを生成します。
     *
     * @param  string $data 文字列
     * @return string ハッシュバイナリ
     */
    public function binary(string $data): string
    {
        return \hash($this->hash_alog, $data, true);
    }

    /**
     * キーと文字列を元にHMACを利用したハッシュ文字列を生成します。
     *
     * @param  string $data 文字列
     * @param  string $key  キー
     * @return string ハッシュ文字列
     */
    public function hmacString(string $data, string $key): string
    {
        return $this->not_use_hmac_algo || !\is_string($key)
         ? \hash($this->hash_alog, $data, false)
         : \hash_hmac($this->hash_alog, $data, $key, false);
    }

    /**
     * キーと文字列を元にハッシュバイナリを生成します。
     *
     * @param  string $data 文字列
     * @param  string $key  キー
     * @return string ハッシュバイナリ
     */
    public function hmacBinary(string $data, string $key): string
    {
        return $this->not_use_hmac_algo || !\is_string($key)
         ? \hash($this->hash_alog, $data, true)
         : \hash_hmac($this->hash_alog, $data, $key, true);
    }

    /**
     * キーとファイルを元にハッシュ文字列を生成します。
     *
     * @param  \SplFileInfo|string $filePath ファイルパス
     * @param  string              $key      キー
     * @return string              ハッシュ文字列
     */
    public function hmacStringFromFile(\SplFileInfo|string $filePath, string $key): string
    {
        \is_string($filePath) ?: $filePath = $filePath->getPathname();

        return $this->not_use_hmac_algo || !\is_string($key)
        ? \hash($this->hash_alog, \file_get_contents($filePath), false)
        : \hash_hmac($this->hash_alog, \file_get_contents($filePath), $key, false);
    }

    /**
     * キーとファイルを元にハッシュバイナリを生成します。
     *
     * @param  \SplFileInfo|string $filePath ファイルパス
     * @param  string              $key      キー
     * @return string              ハッシュバイナリ
     */
    public function hmacBinaryFromFile(\SplFileInfo|string $filePath, string $key): string
    {
        \is_string($filePath) ?: $filePath = $filePath->getPathname();

        return $this->not_use_hmac_algo || !\is_string($key)
        ? \hash($this->hash_alog, \file_get_contents($filePath), true)
        : \hash_hmac($this->hash_alog, \file_get_contents($filePath), $key, true);
    }

    /**
     * ストレッチしたHMACを利用したハッシュ文字列を返します。
     *
     * @param  string $string 文字列
     * @param  string $key    キー
     * @param  int    $count  ストレッチ回数
     * @return string ストレッチしたハッシュ文字列
     */
    public function stretchedHmacString(string $string, string $key, int $count): string
    {
        for ($i = 0;$i < $count;++$i) {
            $string = $this->hmacString($string, $key);
        }

        return $string;
    }

    /**
     * ストレッチしたHMACを利用したハッシュバイナリを生成します。
     *
     * @param  string $data  文字列
     * @param  string $key   キー
     * @param  int    $count ストレッチ回数
     * @return string ストレッチしたハッシュバイナリ
     */
    public function stretchedHmacBinary(string $data, string $key, int $count): string
    {
        for ($i = 0;$i < $count;++$i) {
            $data = $this->hmacBinary($data, $key);
        }

        return $data;
    }

    /**
     * ランダムに生成されたデータを元にストレッチしたHMACを利用したハッシュ文字列を生成して返します。
     *
     * @param int $max_stretching 最大ストレッチ回数
     */
    public function createStretchedHmacString(int $max_stretching = 5): string
    {
        return $this->stretchedHmacString(
            $this->randomizer->getBytes(16),
            $this->randomizer->getBytes(16),
            $this->randomizer->getInt(2, $max_stretching < 5 ? 5 : $max_stretching),
        );
    }

    /**
     * 偽装付きハッシュを構築します。
     *
     * @param  string $string            キー
     * @param  string $salt              ソルト
     * @param  string $hmac_key          HMACキー
     * @param  int    $secret_key_length シークレットキーの長さ
     * @return string 生成した偽装付きハッシュ
     */
    public function createRandomHash(string $string, string $salt, string $hmac_key, int $secret_key_length = self::SECRET_KEY_LENGTH): string
    {
        $secret_hmac_key = $this->createStretchedHmacString();
        $secret_key      = \substr($secret_hmac_key, $secret_key_length, $secret_key_length);
        $secret_hash     = $this->hmacString('\\' . $string . '_' . $salt . '/' . $hmac_key, $secret_key);

        $secret_hash_length = \strlen($secret_hash);

        $string_seed = (string) \hexdec(\hash('crc32b', $string));
        $string_seed = \str_pad($string_seed, $secret_key_length, $string_seed);

        $salt_seed = (string) \hexdec(\hash('crc32b', $salt));
        $salt_seed = \str_pad($salt_seed, $secret_key_length, $salt_seed);

        $index_list = [];

        for ($i = 0;$i < $secret_key_length;++$i) {
            $index = $string_seed[$i] * $salt_seed[$i] * $i + $string_seed[$i] + 1;
            $index = $index > $secret_hash_length ? $secret_hash_length % $index : $index;

            if ($index < 1) {
                ++$index;
            } elseif ($index >= $secret_hash_length) {
                --$index;
            }
            $index_list[] = $index;
        }

        $random_hash = $secret_hash;

        for ($i = 0;$i < $secret_key_length;++$i) {
            $random_hash = \substr($random_hash, 0, $index_list[$i]) . $secret_key[$i] . \substr($random_hash, $index_list[$i]);
        }

        return $random_hash;
    }

    /**
     * 偽装付きハッシュを検証します。
     *
     * @param  string $random_hash       $this->createRandomHashで構築された偽装付きハッシュ
     * @param  string $string            キー
     * @param  string $salt              ソルト
     * @param  string $hmac_key          HMACキー
     * @param  int    $secret_key_length シークレットキーの長さ
     * @return bool   偽装付きハッシュが正当なものならばtrue、そうでなければfalse
     */
    public function verifyRandomHash(string $random_hash, string $string, string $salt, string $hmac_key, int $secret_key_length = self::SECRET_KEY_LENGTH): bool
    {
        $secret_hash_length = \strlen($random_hash) - $secret_key_length;

        $string_seed = (string) \hexdec(\hash('crc32b', $string));
        $string_seed = \str_pad($string_seed, $secret_key_length, $string_seed);

        $salt_seed = (string) \hexdec(\hash('crc32b', $salt));
        $salt_seed = \str_pad($salt_seed, $secret_key_length, $salt_seed);

        $index_list = [];

        for ($i = 0;$i < $secret_key_length;++$i) {
            $index = $string_seed[$i] * $salt_seed[$i] * $i + $string_seed[$i] + 1;
            $index = $index > $secret_hash_length ? $secret_hash_length % $index : $index;

            if ($index < 1) {
                ++$index;
            } elseif ($index >= $secret_hash_length) {
                --$index;
            }
            $index_list[] = $index;
        }
        $kr_index_list = $index_list;

        \krsort($kr_index_list);

        $secret_key  = [];
        $secret_hash = $random_hash;

        foreach ($kr_index_list as $index) {
            $secret_key[] = \substr($secret_hash, $index, 1);
            $secret_hash  = \substr($secret_hash, 0, $index) . \substr($secret_hash, $index + 1);
        }
        \krsort($secret_key);
        $secret_key = \implode('', $secret_key);

        $secret_hash    = $this->hmacString('\\' . $string . '_' . $salt . '/' . $hmac_key, $secret_key);

        for ($i = 0;$i < $secret_key_length;++$i) {
            $secret_hash = \substr($secret_hash, 0, $index_list[$i]) . $secret_key[$i] . \substr($secret_hash, $index_list[$i]);
        }

        return $random_hash === $secret_hash;
    }
}
