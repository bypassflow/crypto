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

namespace bypassflow\crypt\tests\cases;

use bypassflow\crypt\CryptService;
use bypassflow\crypt\infra\Encoder\Base64Encoder;
use bypassflow\crypt\results\EncryptResult;
use bypassflow\crypt\tests\utilities\AbstractTestCase;
use bypassflow\crypt\value_objects\CryptConfig;
use PHPUnit\Framework\Attributes\Test;

/**
 * @internal
 */
final class CryptServiceTest extends AbstractTestCase
{
    #[Test]
    public function factory(): void
    {
        // ==============================================
        $expected = CryptService::class;
        $actual   = CryptService::factory();
        $message  = '';

        $this->assertInstanceOf($expected, $actual, $message);
    }

    #[Test]
    public function factoryFromCryptConfig(): void
    {
        $cryptConfig    = CryptConfig::of(...$this->getDummyCryptConfigData());

        // ==============================================
        $expected = CryptService::class;
        $actual   = CryptService::factoryFromCryptConfig($cryptConfig);
        $message  = '';

        $this->assertInstanceOf($expected, $actual, $message);

        // ==============================================
        $expected = CryptService::factory(...$this->getDummyCryptConfigData());
        $actual   = CryptService::factoryFromCryptConfig($cryptConfig);
        $message  = '';

        $this->assertEquals($expected, $actual, $message);
    }

    #[Test]
    public function factoryForStream(): void
    {
        // ==============================================
        $expected = CryptService::class;
        $actual   = CryptService::factoryForStream();
        $message  = '';

        $this->assertInstanceOf($expected, $actual, $message);
    }

    #[Test]
    public function encryptAndDecrypt1(): void
    {
        $text       = 'test';
        $passphrase = 'pass';
        $base_iv    = '*&J->jnFaHJ->FaH';

        // ==============================================
        // IVはサービスインスタンス単位で固定される
        $cryptService = CryptService::factory();

        $cipherResult1  = $cryptService->encrypt($text, $passphrase);
        $cipherResult2  = $cryptService->encrypt($text, $passphrase);
        $message        = '';

        // ----------------------------------------------
        $expected       = $text;
        $actual         = $cryptService->decrypt($cipherResult1->cipher_text, $passphrase)->text;
        $this->assertEquals($expected, $actual, $message);

        // ----------------------------------------------
        $expected       = $text;
        $actual         = $cryptService->decrypt($cipherResult2->cipher_text, $passphrase)->text;
        $this->assertEquals($expected, $actual, $message);

        // ----------------------------------------------
        $newCryptService    = CryptService::factoryFromCryptConfig($cipherResult1->cryptConfig);
        $expected           = $text;
        $actual             = $newCryptService->decrypt($cipherResult1->cipher_text, $passphrase)->text;
        $message            = '';

        $this->assertEquals($expected, $actual, $message);

        // ----------------------------------------------
        $newCryptService    = CryptService::factoryFromCryptConfig($cipherResult2->cryptConfig);
        $expected           = $text;
        $actual             = $newCryptService->decrypt($cipherResult2->cipher_text, $passphrase)->text;
        $message            = '';

        $this->assertEquals($expected, $actual, $message);

        // ----------------------------------------------
        $cryptServiceWithReGenerateIv =  $cryptService->withReGenerateIv();

        $cipherResult3  = $cryptServiceWithReGenerateIv->encrypt($text, $passphrase);
        $cipherResult4  = $cryptServiceWithReGenerateIv->encrypt($text, $passphrase);
        $message        = '';

        $this->assertSame($cipherResult3->cipher_text, $cipherResult4->cipher_text, $message);
        $this->assertNotSame($cipherResult1->cipher_text, $cipherResult3->cipher_text, $message);

        // ----------------------------------------------
        $expected       = $text;
        $actual         = $cryptServiceWithReGenerateIv->decrypt($cipherResult3->cipher_text, $passphrase)->text;
        $this->assertEquals($expected, $actual, $message);

        // ----------------------------------------------
        $expected       = $text;
        $actual         = $cryptServiceWithReGenerateIv->decrypt($cipherResult4->cipher_text, $passphrase)->text;
        $this->assertEquals($expected, $actual, $message);

        // ----------------------------------------------
        $newCryptService    = CryptService::factoryFromCryptConfig($cipherResult3->cryptConfig);
        $expected           = $text;
        $actual             = $newCryptService->decrypt($cipherResult3->cipher_text, $passphrase)->text;
        $message            = '';

        $this->assertEquals($expected, $actual, $message);

        // ----------------------------------------------
        $newCryptService    = CryptService::factoryFromCryptConfig($cipherResult4->cryptConfig);
        $expected           = $text;
        $actual             = $newCryptService->decrypt($cipherResult4->cipher_text, $passphrase)->text;
        $message            = '';

        $this->assertEquals($expected, $actual, $message);

        // ==============================================
        $cryptService = CryptService::factory(
            iv : $base_iv,
        );

        $expected       = EncryptResult::of(
            outcome     : true,
            cipher_text : '3G/AbhCMk21TUpNqtCZEDw==',
            cryptConfig : CryptConfig::of(
                cipher_algo : 'aes-256-cbc',
                options     : 0,
                iv          : $base_iv,
                tag         : null,
                tag_length  : 16,
                aad         : '',
                encoder     : null,
            ),
            details     : [],
        );
        $actual         = $cryptService->encrypt($text, $passphrase);
        $message        = '';

        $this->assertEquals($expected, $actual, $message);

        // ==============================================
        $cryptService = CryptService::factory();

        $cipherResult   = $cryptService->encrypt($text, $passphrase);
        $message        = '';

        $crypto_context = $cipherResult1->cryptConfig->crypto_context;

        $cryptService   = CryptService::factoryFromCryptContext($crypto_context);

        $expected       = $text;
        $actual         = $cryptService->decrypt($cipherResult1->cipher_text, $passphrase)->text;
        $this->assertEquals($expected, $actual, $message);
    }

    #[Test]
    public function encryptAndDecrypt2(): void
    {
        $text       = 'text';
        $password   = 'pass';

        $error_text = '';

        $message        = '';

        $iv1         = CryptService::createIv(CryptConfig::DEFAULT_CIPHER_METHODS);
        $iv2         = CryptService::createIv(CryptConfig::DEFAULT_CIPHER_METHODS);

        $cryptService1  = CryptService::factory(iv : $iv1);
        $cryptService2  = CryptService::factory(iv : $iv2);

        // ==============================================
        $this->assertNotSame($iv1, $iv2, $message);

        // ==============================================
        $this->assertNotSame($cryptService1->cryptConfig->iv, $cryptService2->cryptConfig->iv, $message);

        // ==============================================
        $this->assertNotSame($cryptService1->encrypt($text, $password)->cipher_text, $cryptService2->encrypt($text, $password)->cipher_text, $message);

        // ==============================================
        $cipher_text1   = $cryptService1->encrypt($text, $password)->cipher_text;
        $cipher_text2   = $cryptService2->encrypt($text, $password)->cipher_text;

        // ----------------------------------------------
        $expected           = $text;
        $actual             = $cryptService1->decrypt($cipher_text1, $password)->text;
        $message            = '';

        $this->assertSame($expected, $actual, $message);

        // ----------------------------------------------
        $expected           = $text;
        $actual             = $cryptService2->decrypt($cipher_text2, $password)->text;
        $message            = '';

        $this->assertSame($expected, $actual, $message);

        // ----------------------------------------------
        $expected           = $error_text;
        $actual             = $cryptService1->decrypt($cipher_text2, $password);
        $message            = '';

        $this->assertFalse($actual->outcome);
        $this->assertSame($expected, $actual->text, $message);

        // ----------------------------------------------
        $expected           = $error_text;
        $actual             = $cryptService2->decrypt($cipher_text1, $password);
        $message            = '';

        $this->assertFalse($actual->outcome);
        $this->assertSame($expected, $actual->text, $message);
    }

    private function getDummyCryptConfigData(): array
    {
        return [
            'cipher_algo'    => CryptConfig::DEFAULT_CIPHER_METHODS,
            'options'        => CryptConfig::DEFAULT_OPENSSL_OPTION,
            'iv'             => 'iv',
            'tag'            => 'tag',
            'tag_length'     => 6,
            'aad'            => 'aad',
            'encoder'        => new Base64Encoder(),
        ];
    }

    private function getDummyCryptConfigDataForStream(): array
    {
        return [
            'cipher_algo'    => CryptConfig::DEFAULT_BYTE_STREAM_CIPHER_METHODS,
            'options'        => CryptConfig::DEFAULT_OPENSSL_OPTION,
            'iv'             => 'iv',
            'tag'            => 'tag',
            'tag_length'     => 6,
            'aad'            => 'aad',
            'encoder'        => new Base64Encoder(),
        ];
    }
}
