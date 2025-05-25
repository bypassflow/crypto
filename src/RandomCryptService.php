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

use bypassflow\crypt\results\DecryptResult;
use bypassflow\crypt\results\RandomEncryptResult;

/**
 * 偽装付き暗号サービス
 */
final class RandomCryptService
{
    /**
     * @var int デフォルトの圧縮率
     */
    public const int COMPRESS_LEVEL = 7;

    /**
     * @var int シークレットキーの長さ
     */
    public const int SECRET_KEY_LENGTH  = 5;

    /**
     * factory
     *
     * @param  CryptService $cryptService 暗号サービス
     * @param  HashService  $hashService  ハッシュサービス
     * @return self         このインスタンス
     */
    public static function factory(
        CryptService $cryptService,
        HashService $hashService,
    ): self {
        return new self(
            $cryptService,
            $hashService,
        );
    }

    /**
     * constructor
     *
     * @param  CryptService $cryptService 暗号サービス
     * @param  HashService  $hashService  ハッシュサービス
     * @return void
     */
    public function __construct(
        private readonly CryptService $cryptService,
        private readonly HashService $hashService,
    ) {
    }

    // ==============================================
    // Encrypt
    // ==============================================
    /**
     * 偽装付きで暗号化します。
     *
     * @param  string              $message           暗号化する文字列
     * @param  string              $password          パスフレーズ
     * @param  string              $salt              ソルト
     * @param  string              $hmac_key          HMACキー
     * @param  int                 $secret_key_length シークレットキーの長さ
     * @return RandomEncryptResult 暗号化結果
     */
    public function encrypt(
        #[\SensitiveParameter]
        string $message,
        #[\SensitiveParameter]
        string $password,
        #[\SensitiveParameter]
        string $salt,
        #[\SensitiveParameter]
        string $hmac_key,
        #[\SensitiveParameter]
        int $secret_key_length = self::SECRET_KEY_LENGTH,
    ): RandomEncryptResult {
        // randamizer
        $secret_hmac_key = $this->hashService->createStretchedHmacString();

        // password1
        $password1  = $this->encodePassword1($message, $password, $salt, $hmac_key, $secret_key_length);

        // binary passwrod 1
        $binary_passwrod_1 = $this->createForwardBinaryPassword($message, $password, $salt, $hmac_key, $secret_key_length);

        // マスタ
        $result1    = $this->cryptService->encrypt($message, $password1, $this->dummyIv($binary_passwrod_1));

        if (!$result1->outcome) {
            throw new \RuntimeException(\sprintf('\openssl_encryptでエラーが発生しています。error_string:%s', \implode(\PHP_EOL, $result1->details)));
        }

        $encoded_message = $result1->cipher_text;

        // secret_key
        $secret_key = \substr(\base64_encode($secret_hmac_key), $secret_key_length, $secret_key_length);

        // passwrod2
        $password2 = $this->hashService->stretchedHmacString($password, $secret_key, $secret_key_length);

        if (\strlen($password2) > 56) {
            $password2 = \substr($password2, -56);
        }

        // binary passwrod 2
        $binary_passwrod_2 = $this->hashService->stretchedHmacBinary($password, $secret_key, $secret_key_length);

        // ダミー
        $result2    = $this->cryptService->encrypt(
            \gzencode($encoded_message, self::COMPRESS_LEVEL, \FORCE_GZIP),
            $password2,
            $this->dummyIv($binary_passwrod_2),
        );

        $encoded_message = \base64_encode($result2->cipher_text);
        $encoded_message = \rtrim($encoded_message, '=');

        // アウトプット
        $encoded_message = \substr($encoded_message, 0, $secret_key_length) . $secret_key . \substr($encoded_message, $secret_key_length);

        // 加工
        $encoded_message_length = \strlen($encoded_message);
        $encoded_message        = \str_pad($encoded_message, $encoded_message_length + $encoded_message_length % 4, '=');

        // 処理の終了
        return RandomEncryptResult::of(
            outcome     : $result1->outcome,
            cipher_text : $encoded_message,
            cryptConfig : $result1->cryptConfig,
            details     : $result1->details,
        );
    }

    // ==============================================
    // Decrypt
    // ==============================================
    /**
     * 偽装した暗号文を復号します。
     *
     * @param  string        $encoded_message   暗号文
     * @param  string        $password          パスフレーズ
     * @param  string        $salt              ソルト
     * @param  string        $hmac_key          HMACキー
     * @param  int           $secret_key_length シークレットキーの長さ
     * @return DecryptResult 復号されたデータ
     */
    public function decrypt(
        string $encoded_message,
        #[\SensitiveParameter]
        string $password,
        #[\SensitiveParameter]
        string $salt,
        #[\SensitiveParameter]
        string $hmac_key,
        #[\SensitiveParameter]
        int $secret_key_length = self::SECRET_KEY_LENGTH,
    ): DecryptResult {
        if (!\is_string($encoded_message)) {
            throw new \ErrorException('暗号文が無効です。');
        }

        // password1
        $password1  = $this->encodePassword1($encoded_message, $password, $salt, $hmac_key, $secret_key_length);

        // binary passwrod 1
        $binary_passwrod_1 = $this->createForwardBinaryPassword($encoded_message, $password, $salt, $hmac_key, $secret_key_length);

        // 複合テスト
        // 逆加工
        $encoded_message = \trim($encoded_message);
        $encoded_message = \rtrim($encoded_message, '=');

        // secret key
        $secret_key = \substr($encoded_message, $secret_key_length, $secret_key_length);

        // インプット
        $encoded_message = \substr($encoded_message, 0, $secret_key_length) . \substr($encoded_message, \strlen($secret_key) * 2);

        // passwrod2
        $password2 = $this->hashService->stretchedHmacString($password, $secret_key, $secret_key_length);

        if (\strlen($password2) > 56) {
            $password2 = \substr($password2, -56);
        }

        // binary passwrod 2
        $binary_passwrod_2 = $this->hashService->stretchedHmacBinary($password, $secret_key, $secret_key_length);

        // ダミー
        $encoded_message_length = \strlen($encoded_message);
        $encoded_message        = \str_pad($encoded_message, $encoded_message_length + $encoded_message_length % 4, '=');

        $decrypted_dummy    = $this->cryptService->decrypt(\base64_decode($encoded_message, true), $password2, $this->dummyIv($binary_passwrod_2));

        $encoded_message    = $decrypted_dummy->text;

        if ($encoded_message === false) {
            throw new \RuntimeException('復号に失敗しました。');
        }

        $encoded_message = @\gzdecode($encoded_message);

        // マスタ
        return $this->cryptService->decrypt($encoded_message, $password1, $this->dummyIv($binary_passwrod_1));
    }

    // ==============================================
    // Utility
    // ==============================================
    /**
     * encodePassword1
     *
     * @param  string $message           暗号化する文字列
     * @param  string $password          パスフレーズ
     * @param  string $salt              ソルト
     * @param  string $hmac_key          HMACキー
     * @param  int    $secret_key_length シークレットキーの長さ
     * @return string passwrod01
     */
    private function encodePassword1(string $message, string $password, string $salt, string $hmac_key, int $secret_key_length): string
    {
        $password1 = $this->createForwardPassword($message, $password, $salt, $hmac_key, $secret_key_length);

        if (\strlen($password1) > 56) {
            $password1 = \substr($password1, -56);
        }

        return $password1;
    }

    /**
     * ダミーIVを構築して返します。
     *
     * @param  string $binary 対象とするバイナリ
     * @return string ダミーIV
     */
    private function dummyIv(string $binary): string
    {
        $iv     = $binary;
        $length = \openssl_cipher_iv_length($this->cryptService->cryptConfig->cipher_algo);

        for (;\strlen($iv) < $length;) {
            if (\strlen($iv) >= $length) {
                return \substr($iv, 0, $length);
            }

            $iv .= $binary;
        }

        return \substr($iv, 0, $length);
    }

    /**
     * フォワードパスワードを構築します。
     *
     * @param string $text              暗号化する文字列
     * @param string $salt              ソルト
     * @param string $hmac_key          HMACキー
     * @param int    $secret_key_length シークレットキーの長さ
     */
    private function createForwardPassword(
        string $text,
        string $password,
        string $salt,
        string $hmac_key,
        int $secret_key_length = self::SECRET_KEY_LENGTH,
    ) {
        $hash_password = \sprintf('\\\s_\s_\s/', $text, $password, $salt);

        return $this->hashService->stretchedHmacString($hash_password, $hmac_key, $secret_key_length) . $hash_password;
    }

    /**
     * フォワードバイナリパスワードを構築します。
     *
     * @param string $text              暗号化する文字列
     * @param string $salt              ソルト
     * @param string $hmac_key          HMACキー
     * @param int    $secret_key_length シークレットキーの長さ
     */
    private function createForwardBinaryPassword(
        string $text,
        string $password,
        string $salt,
        string $hmac_key,
        int $secret_key_length = self::SECRET_KEY_LENGTH,
    ) {
        $hash_password = \sprintf('\\\s_\s_\s/', $text, $password, $salt);

        return $this->hashService->stretchedHmacBinary($hash_password, $hmac_key, $secret_key_length) . $hash_password;
    }
}
