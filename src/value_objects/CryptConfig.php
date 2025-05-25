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

use bypassflow\crypt\infra\Encoder\interfaces\EncoderInterface;

/**
 * 暗号・複合に必要なデータセット
 */
final class CryptConfig
{
    /**
     * @var string デフォルトとして使う暗号化メソッド
     */
    public const string DEFAULT_CIPHER_METHODS  = 'aes-256-cbc';

    /**
     * @var string バイトストリーム用にデフォルトとして使う暗号化メソッド
     */
    public const string DEFAULT_BYTE_STREAM_CIPHER_METHODS  = 'aes-256-cfb';

    /**
     * @var int デフォルトとして使うOPENSSL OPTION
     */
    public const int DEFAULT_OPENSSL_OPTION = \OPENSSL_RAW_DATA & \OPENSSL_ZERO_PADDING;

    /**
     * @var array 復号コンテキスト
     */
    public array $crypto_context {
        get {
            return [
                'cipher_algo' => $this->cipher_algo,
                'options'     => $this->options,
                'iv'          => $this->iv  === null ? $this->iv : \base64_encode($this->iv),
                'tag'         => $this->tag === null ? $this->tag : \base64_encode($this->tag),
                'tag_length'  => $this->tag_length,
                'aad'         => $this->aad,
            ];
        }
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
    public static function of(
        string $cipher_algo = self::DEFAULT_CIPHER_METHODS,
        int $options = self::DEFAULT_OPENSSL_OPTION,
        #[\SensitiveParameter]
        ?string $iv = null,
        #[\SensitiveParameter]
        ?string $tag = null,
        ?int $tag_length = null,
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
    public static function ofFromCryptContext(
        #[\SensitiveParameter]
        array $crypto_context,
    ): self {
        return new self(
            $crypto_context['cipher_algo'],
            $crypto_context['options'],
            $crypto_context['iv']  === null ? $crypto_context['iv'] : \base64_decode($crypto_context['iv'], true),
            $crypto_context['tag'] === null ? $crypto_context['tag'] : \base64_decode($crypto_context['tag'], true),
            $crypto_context['tag_length'],
            $crypto_context['aad'],
        );
    }

    /**
     * バイトストリーム用factory
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
    public static function ofForStream(
        string $cipher_algo = self::DEFAULT_BYTE_STREAM_CIPHER_METHODS,
        int $options = self::DEFAULT_OPENSSL_OPTION,
        #[\SensitiveParameter]
        ?string $iv = null,
        #[\SensitiveParameter]
        ?string $tag = null,
        ?int $tag_length = null,
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
     * constructor
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
    public function __construct(
        public readonly string $cipher_algo = self::DEFAULT_CIPHER_METHODS,
        public readonly int $options = self::DEFAULT_OPENSSL_OPTION,
        #[\SensitiveParameter]
        public readonly ?string $iv = null,
        #[\SensitiveParameter]
        public readonly ?string $tag = null,
        public readonly ?int $tag_length = null,
        #[\SensitiveParameter]
        public readonly string $aad = '',
        public readonly ?EncoderInterface $encoder = null,
    ) {
    }

    /**
     * withIv
     *
     * @param  string $iv 初期化ベクトル
     * @return self   このインスタンス
     */
    public function withIv(
        #[\SensitiveParameter]
        string $iv,
    ): self {
        return new self(
            $this->cipher_algo,
            $this->options,
            $iv,
            $this->tag,
            $this->tag_length,
            $this->aad,
            $this->encoder,
        );
    }

    /**
     * withTag
     *
     * @param  string $tag AEAD 暗号モード (GCM または CCM) を使う場合の認証タグ
     * @return self   このインスタンス
     */
    public function withTag(
        #[\SensitiveParameter]
        null|string $tag,
    ): self {
        return new self(
            $this->cipher_algo,
            $this->options,
            $this->iv,
            $tag,
            $this->tag_length,
            $this->aad,
            $this->encoder,
        );
    }
}
