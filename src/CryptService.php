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

use bypassflow\crypt\infra\Encoder\interfaces\EncoderInterface;
use bypassflow\crypt\results\DecryptResult;
use bypassflow\crypt\results\EncryptResult;
use bypassflow\crypt\value_objects\CryptConfig;

/**
 * OpenSslを用いた暗号サービス
 */
final class CryptService
{
    /**
     * @var CryptConfig 暗号・複合に必要なデータセット
     */
    public readonly CryptConfig $cryptConfig;

    /**
     * factory
     *
     * @param  CryptConfig $cryptConfig 暗号・複合に必要なデータセット
     * @return self        このインスタンス
     */
    public static function factoryFromCryptConfig(
        CryptConfig $cryptConfig,
    ): self {
        return new self(
            $cryptConfig->cipher_algo,
            $cryptConfig->options,
            $cryptConfig->iv,
            $cryptConfig->tag,
            $cryptConfig->tag_length,
            $cryptConfig->aad,
            $cryptConfig->encoder,
        );
    }

    /**
     * factory
     *
     * @param  string                $cipher_algo 暗号メソッド
     * @param  int                   $options     オプション
     * @param  null|string           $iv          初期化ベクトル
     * @param  null|string           $tag         AEAD 暗号モード (GCM または CCM) を使う場合の認証タグ
     * @param  null|int              $tag_length  認証タグの長さ
     * @param  string                $aad         追加の認証済みデータ
     * @param  null|EncoderInterface $encoder     エンコーダ
     * @return self                  このインスタンス
     */
    public static function factory(
        string $cipher_algo = CryptConfig::DEFAULT_CIPHER_METHODS,
        int $options = CryptConfig::DEFAULT_OPENSSL_OPTION,
        #[\SensitiveParameter]
        ?string $iv = null,
        #[\SensitiveParameter]
        ?string $tag = null,
        int $tag_length = 16,
        #[\SensitiveParameter]
        string $aad = '',
        ?EncoderInterface $encoder = null,
    ): self {
        return new self(
            $cipher_algo,
            $options,
            $iv,
            $tag,
            $tag_length,
            $aad,
            $encoder,
        );
    }

    /**
     * crypto_contextプロパティ経由で取得された復号コンテキストを元にしたfactory
     *
     * @param  array $crypto_context 復号コンテキスト
     * @return self  このインスタンス
     */
    public static function factoryFromCryptContext(
        #[\SensitiveParameter]
        array $crypto_context,
    ): self {
        return self::factoryFromCryptConfig(CryptConfig::ofFromCryptContext($crypto_context));
    }

    /**
     * factory
     *
     * @param  int                   $options    オプション
     * @param  null|string           $iv         初期化ベクトル
     * @param  null|string           $tag        AEAD 暗号モード (GCM または CCM) を使う場合の認証タグ
     * @param  null|int              $tag_length 認証タグの長さ
     * @param  string                $aad        追加の認証済みデータ
     * @param  null|EncoderInterface $encoder    エンコーダ
     * @return self                  このインスタンス
     */
    public static function factoryForStream(
        int $options = CryptConfig::DEFAULT_OPENSSL_OPTION,
        #[\SensitiveParameter]
        ?string $iv = null,
        #[\SensitiveParameter]
        ?string $tag = null,
        int $tag_length = 16,
        #[\SensitiveParameter]
        string $aad = '',
        ?EncoderInterface $encoder = null,
    ): self {
        return new self(
            CryptConfig::DEFAULT_BYTE_STREAM_CIPHER_METHODS,
            $options,
            $iv,
            $tag,
            $tag_length,
            $aad,
            $encoder,
        );
    }

    /**
     * IVを生成して返します。
     *
     * @param  string $cipher_algo 暗号化メソッド
     * @return string IV
     */
    public static function createIv(string $cipher_algo): string
    {
        return \openssl_random_pseudo_bytes(\openssl_cipher_iv_length($cipher_algo));
    }

    /**
     * constructor
     *
     * @param  string                $cipher_algo 暗号メソッド
     * @param  int                   $options     オプション
     * @param  null|string           $iv          初期化ベクトル
     * @param  null|string           $tag         AEAD 暗号モード (GCM または CCM) を使う場合の認証タグ
     * @param  null|int              $tag_length  認証タグの長さ
     * @param  string                $aad         追加の認証済みデータ
     * @param  null|EncoderInterface $encoder     エンコーダ
     * @return void
     */
    public function __construct(
        string $cipher_algo = CryptConfig::DEFAULT_CIPHER_METHODS,
        int $options = CryptConfig::DEFAULT_OPENSSL_OPTION,
        #[\SensitiveParameter]
        ?string $iv = null,
        #[\SensitiveParameter]
        ?string $tag = null,
        int $tag_length = 16,
        #[\SensitiveParameter]
        ?string $aad = '',
        ?EncoderInterface $encoder = null,
    ) {
        static $openssl_get_cipher_methods = \openssl_get_cipher_methods();

        if (!\in_array($cipher_algo, $openssl_get_cipher_methods, true)) {
            throw new \ErrorException(\sprintf('利用できない暗号メソッドを指定されました。cipher_algo:%s', $cipher_algo));
        }

        $this->cryptConfig  = CryptConfig::of(
            $cipher_algo,
            $options,
            $iv ?? self::createIv($cipher_algo),
            $tag,
            $tag_length,
            $aad,
            $encoder,
        );
    }

    // ==============================================
    // Encrypt
    // ==============================================
    /**
     * 文字列を暗号化して結果を返します。
     *
     * @param  string        $text       暗号化する文字列
     * @param  string        $passphrase パスフレーズ
     * @param  null|string   $iv         IV
     * @return EncryptResult 暗号化されたデータ
     */
    public function encrypt(
        #[\SensitiveParameter]
        string $text,
        #[\SensitiveParameter]
        string $passphrase,
        #[\SensitiveParameter]
        ?string $iv = null,
    ): EncryptResult {
        $error_string_list = [];

        for (;false !== $error_string = \openssl_error_string();) {
            $error_string_list[]    = $error_string;
        }

        if (!empty($error_string_list)) {
            throw new \RuntimeException(\sprintf('先行する\openssl_encryptまたは\openssl_decryptでエラーが発生しています。error_string:%s', \implode(\PHP_EOL, $error_string_list)));
        }

        $tag = null;

        $current_iv = $iv ?? $this->cryptConfig->iv;

        $cipher_text = \openssl_encrypt(
            $text,
            $this->cryptConfig->cipher_algo,
            $this->generateKey($passphrase, $current_iv),
            $this->cryptConfig->options,
            $current_iv,
            $tag,
            $this->cryptConfig->aad,
            $this->cryptConfig->tag_length,
        );

        $error_string_list = [];

        for (;false !== $error_string = \openssl_error_string();) {
            $error_string_list[]    = $error_string;
        }

        if (empty($error_string_list) && $this->cryptConfig->encoder !== null) {
            $encoder        = $this->cryptConfig->encoder;
            $cipher_text    = $encoder->encode($cipher_text);
        }

        return EncryptResult::of(
            outcome     : empty($error_string_list),
            cipher_text : $cipher_text,
            cryptConfig : $this->cryptConfig->withTag(
                $tag,
            ),
            details     : $error_string_list,
        );
    }

    // ==============================================
    // Decrypt
    // ==============================================
    /**
     * 文字列を復号して結果を返します。
     *
     * @param  string        $cipher_text 復号する文字列
     * @param  string        $passphrase  パスフレーズ
     * @param  null|string   $iv          IV
     * @return DecryptResult 復号されたデータ
     */
    public function decrypt(
        string $cipher_text,
        #[\SensitiveParameter]
        string $passphrase,
        #[\SensitiveParameter]
        ?string $iv = null,
    ): DecryptResult {
        $error_string_list = [];

        for (;false !== $error_string = \openssl_error_string();) {
            $error_string_list[]    = $error_string;
        }

        if (!empty($error_string_list)) {
            throw new \RuntimeException(\sprintf('先行する\openssl_encryptまたは\openssl_decryptでエラーが発生しています。error_string:%s', \implode(\PHP_EOL, $error_string_list)));
        }

        if ($this->cryptConfig->encoder !== null) {
            $encoder        = $this->cryptConfig->encoder;
            $cipher_text    = $encoder->decode($cipher_text);
        }

        $current_iv = $iv ?? $this->cryptConfig->iv;

        $text = \openssl_decrypt(
            $cipher_text,
            $this->cryptConfig->cipher_algo,
            $this->generateKey($passphrase, $current_iv),
            $this->cryptConfig->options,
            $current_iv,
            $this->cryptConfig->tag,
            $this->cryptConfig->aad,
        );

        $error_string_list = [];

        for (;false !== $error_string = \openssl_error_string();) {
            $error_string_list[]    = $error_string;
        }

        $outcome = $text !== false && empty($error_string_list);

        return DecryptResult::of(
            outcome     : $outcome,
            text        : $outcome ? $text : '',
            cryptConfig : $this->cryptConfig,
            details     : $error_string_list,
        );
    }

    /**
     * IVを再生成した暗号サービスを返します。
     *
     * @return self IVを再生成した暗号サービス
     */
    public function withReGenerateIv(): self
    {
        return self::factoryFromCryptConfig($this->cryptConfig->withIv(self::createIv($this->cryptConfig->cipher_algo)));
    }

    /**
     * 鍵を作成しかえします。
     *
     * @param  string $passphrase パスフレーズ
     * @param  string $iv         IV
     * @return string 鍵
     */
    private function generateKey(string $passphrase, string $iv): string
    {
        $length = \openssl_cipher_key_length($this->cryptConfig->cipher_algo);

        $key    = $iv . $passphrase;
        $switch = false;

        for (;\strlen($key) < $length;) {
            if (\strlen($key) >= $length) {
                return \substr($key, 0, $length);
            }

            $key .= $switch = !$switch ? $passphrase : $iv;
        }

        return \substr($key, 0, $length);
    }
}
