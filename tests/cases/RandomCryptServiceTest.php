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
use bypassflow\crypt\HashService;
use bypassflow\crypt\RandomCryptService;
use bypassflow\crypt\tests\utilities\AbstractTestCase;
use bypassflow\crypt\value_objects\CryptConfig;
use PHPUnit\Framework\Attributes\Test;

/**
 * @internal
 */
final class RandomCryptServiceTest extends AbstractTestCase
{
    #[Test]
    public function factory(): void
    {
        // ==============================================
        $expected = RandomCryptService::class;
        $actual   = RandomCryptService::factory(
            $this->createCrypteService(),
            $this->createHashService(),
        );
        $message  = '';

        $this->assertInstanceOf($expected, $actual, $message);
    }

    #[Test]
    public function encryptAndDecrypt1(): void
    {
        $text       = 'text';
        $password   = 'pass';
        $salt       = 'salt';
        $hmac_key   = 'key';

        // ==============================================
        $randomCryptService = RandomCryptService::factory(
            $this->createCrypteService(),
            $this->createHashService(),
        );

        $cipherResult1  = $randomCryptService->encrypt(
            $text,
            $password,
            $salt,
            $hmac_key,
        );

        $cipherResult2  = $randomCryptService->encrypt(
            $text,
            $password,
            $salt,
            $hmac_key,
        );

        $message        = '';

        $this->assertNotSame($cipherResult1->cipher_text, $cipherResult2->cipher_text, $message);

        // ==============================================
        $expected = $text;
        $actual   = $randomCryptService->decrypt(
            $cipherResult1->cipher_text,
            $password,
            $salt,
            $hmac_key,
        )->text;

        $message        = '';

        $this->assertSame($expected, $actual, $message);

        // ----------------------------------------------
        $expected = $text;
        $actual   = $randomCryptService->decrypt(
            $cipherResult2->cipher_text,
            $password,
            $salt,
            $hmac_key,
        )->text;

        $message        = '';

        $this->assertSame($expected, $actual, $message);
    }

    #[Test]
    public function encryptAndDecrypt2(): void
    {
        $text       = 'text';
        $password   = 'pass';
        $salt       = 'salt';
        $hmac_key   = 'key';

        // ==============================================
        $randomCryptService = RandomCryptService::factory(
            $this->createCrypteService(),
            $this->createHashService(),
        );

        $cipherResult1  = $randomCryptService->encrypt(
            $text,
            $password,
            $salt,
            $hmac_key,
        );

        $cipherResult2  = $randomCryptService->encrypt(
            $text,
            $password,
            $salt,
            $hmac_key,
        );

        $message        = '';

        $this->assertNotSame($cipherResult1->cipher_text, $cipherResult2->cipher_text, $message);

        // ==============================================
        $randomCryptService = RandomCryptService::factory(
            $this->createCrypteService(),
            $this->createHashService(),
        );

        // ----------------------------------------------
        $expected = $text;
        $actual   = $randomCryptService->decrypt(
            $cipherResult1->cipher_text,
            $password,
            $salt,
            $hmac_key,
        )->text;

        $message        = '';

        $this->assertSame($expected, $actual, $message);

        // ----------------------------------------------
        $expected = $text;
        $actual   = $randomCryptService->decrypt(
            $cipherResult2->cipher_text,
            $password,
            $salt,
            $hmac_key,
        )->text;

        $message        = '';

        $this->assertSame($expected, $actual, $message);

        // ==============================================
        $randomCryptService = RandomCryptService::factory(
            CryptService::factoryFromCryptConfig($cipherResult1->cryptConfig),
            $this->createHashService(),
        );

        // ----------------------------------------------
        $expected = $text;
        $actual   = $randomCryptService->decrypt(
            $cipherResult1->cipher_text,
            $password,
            $salt,
            $hmac_key,
        )->text;

        $message        = '';

        $this->assertSame($expected, $actual, $message);

        // ----------------------------------------------
        $expected = $text;
        $actual   = $randomCryptService->decrypt(
            $cipherResult2->cipher_text,
            $password,
            $salt,
            $hmac_key,
        )->text;

        $message        = '';

        $this->assertSame($expected, $actual, $message);
    }

    #[Test]
    public function encryptAndDecrypt3(): void
    {
        $text       = 'text';
        $password   = 'pass';
        $salt       = 'salt';
        $hmac_key   = 'key';

        $message        = '';

        $iv1         = CryptService::createIv(CryptConfig::DEFAULT_CIPHER_METHODS);
        $iv2         = CryptService::createIv(CryptConfig::DEFAULT_CIPHER_METHODS);
        $hashService = $this->createHashService();

        $randomCryptService1 = RandomCryptService::factory(
            CryptService::factory(iv : $iv1),
            $hashService,
        );

        $randomCryptService2 = RandomCryptService::factory(
            CryptService::factory(iv : $iv2),
            $hashService,
        );

        // ==============================================
        $this->assertNotSame($iv1, $iv2, $message);

        // ==============================================
        $cipherResult1  = $randomCryptService1->encrypt(
            $text,
            $password,
            $salt,
            $hmac_key,
        );

        $expected   = $text;
        $actual     = $randomCryptService2->decrypt(
            $cipherResult1->cipher_text,
            $password,
            $salt,
            $hmac_key,
        )->text;

        $message        = '';

        $this->assertSame($expected, $actual, $message);
    }

    private function createCrypteService(): CryptService
    {
        return CryptService::factory();
    }

    private function createHashService(): HashService
    {
        return HashService::factory();
    }
}
