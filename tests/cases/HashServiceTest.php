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

use bypassflow\crypt\HashService;
use bypassflow\crypt\tests\utilities\AbstractTestCase;
use bypassflow\crypt\tests\utilities\Random\Engine\DummyRandomEngine;
use bypassflow\crypt\tests\utilities\Utility;
use PHPUnit\Framework\Attributes\Test;

/**
 * @internal
 */
final class HashServiceTest extends AbstractTestCase
{
    #[Test]
    public function factory(): void
    {
        // ==============================================
        $expected = HashService::class;
        $actual   = HashService::factory();
        $message  = '';

        $this->assertInstanceOf($expected, $actual, $message);

        // ==============================================
        $expected = HashService::factory(
            randomizer : new \Random\Randomizer(new DummyRandomEngine('qwerqwer')),
        )->string('1');

        $actual = HashService::factory(
            randomizer : new \Random\Randomizer(new DummyRandomEngine('asdf')),
        )->string('1');

        $this->assertSame($expected, $actual, $message);
    }

    #[Test]
    public function string(): void
    {
        $base_message   = 'test';

        // ==============================================
        $hashService = HashService::factory();

        $expected = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';
        $actual   = $hashService->string($base_message);
        $message  = '';

        $this->assertSame($expected, $actual, $message);

        // ==============================================
        $hashService = HashService::factory('sha512');

        $expected = 'ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff';
        $actual   = $hashService->string($base_message);
        $message  = '';

        $this->assertSame($expected, $actual, $message);

        // ==============================================
        $hashService = HashService::factory('sha256');

        $expected = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';
        $actual   = $hashService->string($base_message);
        $message  = '';

        $this->assertSame($expected, $actual, $message);
    }

    #[Test]
    public function binary(): void
    {
        $base_message   = 'test';

        // ==============================================
        $hashService = HashService::factory();

        $expected = \base64_decode('n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=', true);
        $actual   = $hashService->binary($base_message);
        $message  = '';

        $this->assertSame($expected, $actual, $message);

        // ==============================================
        $hashService = HashService::factory('sha512');

        $expected = \base64_decode('7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==', true);
        $actual   = $hashService->binary($base_message);
        $message  = '';

        $this->assertSame($expected, $actual, $message);

        // ==============================================
        $hashService = HashService::factory('sha256');
        $expected    = \base64_decode('n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg=', true);
        $actual      = $hashService->binary($base_message);
        $message     = '';

        $this->assertSame($expected, $actual, $message);
    }

    #[Test]
    public function hmacString(): void
    {
        $base_message   = 'test';
        $key            = 'key';

        // ==============================================
        $hashService = HashService::factory();

        $expected = '02afb56304902c656fcb737cdd03de6205bb6d401da2812efd9b2d36a08af159';
        $actual   = $hashService->hmacString($base_message, $key);
        $message  = '';

        $this->assertSame($expected, $actual, $message);

        // ==============================================
        $hashService = HashService::factory('sha512');

        $expected = '287a0fb89a7fbdfa5b5538636918e537a5b83065e4ff331268b7aaa115dde047a9b0f4fb5b828608fc0b6327f10055f7637b058e9e0dbb9e698901a3e6dd461c';
        $actual   = $hashService->hmacString($base_message, $key);
        $message  = '';

        $this->assertSame($expected, $actual, $message);

        // ==============================================
        $hashService = HashService::factory('sha256');

        $expected = '02afb56304902c656fcb737cdd03de6205bb6d401da2812efd9b2d36a08af159';
        $actual   = $hashService->hmacString($base_message, $key);
        $message  = '';

        $this->assertSame($expected, $actual, $message);
    }

    #[Test]
    public function hmacBinary(): void
    {
        $base_message   = 'test';
        $key            = 'key';

        // ==============================================
        $hashService = HashService::factory();

        $expected = \base64_decode('Aq+1YwSQLGVvy3N83QPeYgW7bUAdooEu/ZstNqCK8Vk=', true);
        $actual   = $hashService->hmacBinary($base_message, $key);
        $message  = '';

        $this->assertSame($expected, $actual, $message);

        // ==============================================
        $hashService = HashService::factory('sha512');

        $expected = \base64_decode('KHoPuJp/vfpbVThjaRjlN6W4MGXk/zMSaLeqoRXd4EepsPT7W4KGCPwLYyfxAFX3Y3sFjp4Nu55piQGj5t1GHA==', true);
        $actual   = $hashService->hmacBinary($base_message, $key);
        $message  = '';

        $this->assertSame($expected, $actual, $message);

        // ==============================================
        $hashService = HashService::factory('sha256');
        $expected    = \base64_decode('Aq+1YwSQLGVvy3N83QPeYgW7bUAdooEu/ZstNqCK8Vk=', true);
        $actual      = $hashService->hmacBinary($base_message, $key);
        $message     = '';

        $this->assertSame($expected, $actual, $message);
    }

    #[Test]
    public function hmacStringFromFile(): void
    {
        $testFile   = Utility::factory()->getTestFile();
        $key        = 'key';

        // ==============================================
        $hashService = HashService::factory();

        $expected = '02afb56304902c656fcb737cdd03de6205bb6d401da2812efd9b2d36a08af159';
        $actual   = $hashService->hmacStringFromFile($testFile, $key);
        $message  = '';

        $this->assertSame($expected, $actual, $message);

        // ----------------------------------------------
        $hashService = HashService::factory('sha512');

        $expected = '287a0fb89a7fbdfa5b5538636918e537a5b83065e4ff331268b7aaa115dde047a9b0f4fb5b828608fc0b6327f10055f7637b058e9e0dbb9e698901a3e6dd461c';
        $actual   = $hashService->hmacStringFromFile($testFile, $key);
        $message  = '';

        $this->assertSame($expected, $actual, $message);

        // ----------------------------------------------
        $hashService = HashService::factory('sha256');

        $expected = '02afb56304902c656fcb737cdd03de6205bb6d401da2812efd9b2d36a08af159';
        $actual   = $hashService->hmacStringFromFile($testFile, $key);
        $message  = '';

        $this->assertSame($expected, $actual, $message);

        $testFile   = Utility::factory()->getTestFile();

        $key            = 'key';

        // ==============================================
        $testFile   = Utility::factory()->getTestFile()->getPathname();

        // ----------------------------------------------
        $hashService = HashService::factory();

        $expected = '02afb56304902c656fcb737cdd03de6205bb6d401da2812efd9b2d36a08af159';
        $actual   = $hashService->hmacStringFromFile($testFile, $key);
        $message  = '';

        $this->assertSame($expected, $actual, $message);

        // ==============================================
        $hashService = HashService::factory('sha512');

        $expected = '287a0fb89a7fbdfa5b5538636918e537a5b83065e4ff331268b7aaa115dde047a9b0f4fb5b828608fc0b6327f10055f7637b058e9e0dbb9e698901a3e6dd461c';
        $actual   = $hashService->hmacStringFromFile($testFile, $key);
        $message  = '';

        $this->assertSame($expected, $actual, $message);

        // ==============================================
        $hashService = HashService::factory('sha256');

        $expected = '02afb56304902c656fcb737cdd03de6205bb6d401da2812efd9b2d36a08af159';
        $actual   = $hashService->hmacStringFromFile($testFile, $key);
        $message  = '';

        $this->assertSame($expected, $actual, $message);
    }

    #[Test]
    public function hmacBinaryFromFile(): void
    {
        $testFile   = Utility::factory()->getTestFile();
        $key        = 'key';

        // ==============================================
        $hashService = HashService::factory();

        $expected = \base64_decode('Aq+1YwSQLGVvy3N83QPeYgW7bUAdooEu/ZstNqCK8Vk=', true);
        $actual   = $hashService->hmacBinaryFromFile($testFile, $key);
        $message  = '';

        $this->assertSame($expected, $actual, $message);

        // ----------------------------------------------
        $hashService = HashService::factory('sha512');

        $expected = \base64_decode('KHoPuJp/vfpbVThjaRjlN6W4MGXk/zMSaLeqoRXd4EepsPT7W4KGCPwLYyfxAFX3Y3sFjp4Nu55piQGj5t1GHA==', true);
        $actual   = $hashService->hmacBinaryFromFile($testFile, $key);
        $message  = '';

        $this->assertSame($expected, $actual, $message);

        // ----------------------------------------------
        $hashService = HashService::factory('sha256');
        $expected    = \base64_decode('Aq+1YwSQLGVvy3N83QPeYgW7bUAdooEu/ZstNqCK8Vk=', true);
        $actual      = $hashService->hmacBinaryFromFile($testFile, $key);
        $message     = '';

        $this->assertSame($expected, $actual, $message);

        // ==============================================
        $testFile   = Utility::factory()->getTestFile()->getPathname();

        // ----------------------------------------------
        $hashService = HashService::factory();

        $expected = \base64_decode('Aq+1YwSQLGVvy3N83QPeYgW7bUAdooEu/ZstNqCK8Vk=', true);
        $actual   = $hashService->hmacBinaryFromFile($testFile, $key);
        $message  = '';

        $this->assertSame($expected, $actual, $message);

        // ----------------------------------------------
        $hashService = HashService::factory('sha512');

        $expected = \base64_decode('KHoPuJp/vfpbVThjaRjlN6W4MGXk/zMSaLeqoRXd4EepsPT7W4KGCPwLYyfxAFX3Y3sFjp4Nu55piQGj5t1GHA==', true);
        $actual   = $hashService->hmacBinaryFromFile($testFile, $key);
        $message  = '';

        $this->assertSame($expected, $actual, $message);

        // ----------------------------------------------
        $hashService = HashService::factory('sha256');
        $expected    = \base64_decode('Aq+1YwSQLGVvy3N83QPeYgW7bUAdooEu/ZstNqCK8Vk=', true);
        $actual      = $hashService->hmacBinaryFromFile($testFile, $key);
        $message     = '';

        $this->assertSame($expected, $actual, $message);
    }

    #[Test]
    public function stretchedHmacString(): void
    {
        $count          = 5;
        $base_message   = 'test';
        $key            = 'key';

        // ==============================================
        $hashService = HashService::factory();

        $expected = '23a2509ab3c77cb8a1c05845be18611c7b2036a9f5ac02ce9d3af73f13fa1ebf';
        $actual   = $hashService->stretchedHmacString($base_message, $key, $count);
        $message  = '';

        $this->assertSame($expected, $actual, $message);

        // ==============================================
        $hashService = HashService::factory();

        $expected = '4f97584a5da34ff20dc58930ab867ee49e2e6fb696433c13bafd430268a836d7';
        $actual   = $hashService->stretchedHmacString($base_message, $key, 1 + $count);
        $message  = '';

        $this->assertSame($expected, $actual, $message);

        // ==============================================
        $hashService = HashService::factory('sha512');

        $expected = 'c8a62a723b8823e96e4e84dc5da8b3c6df757453e08b403832fc69085b2ba1fad9e306b96aacbcab2ab6bc312416b08e896d1cf9ec399c0d29a1e8511752caa8';
        $actual   = $hashService->stretchedHmacString($base_message, $key, $count);
        $message  = '';

        $this->assertSame($expected, $actual, $message);

        // ==============================================
        $hashService = HashService::factory('sha256');

        $expected = '23a2509ab3c77cb8a1c05845be18611c7b2036a9f5ac02ce9d3af73f13fa1ebf';
        $actual   = $hashService->stretchedHmacString($base_message, $key, $count);
        $message  = '';

        $this->assertSame($expected, $actual, $message);
    }

    #[Test]
    public function stretchedHmacBinary(): void
    {
        $count          = 5;
        $base_message   = 'test';
        $key            = 'key';

        // ==============================================
        $hashService = HashService::factory();

        $expected = \base64_decode('CBstMy4QPs45o4A/++3CLp8u6PlLRzUe63wBruMjd1g=', true);
        $actual   = $hashService->stretchedHmacBinary($base_message, $key, $count);
        $message  = '';

        $this->assertSame($expected, $actual, $message);

        // ==============================================
        $hashService = HashService::factory();

        $expected = \base64_decode('1rE3BeOvGE6zD3Py5WJlJAI88kzKkkb1j5hYIxs5EMM=', true);
        $actual   = $hashService->stretchedHmacBinary($base_message, $key, 1 + $count);
        $message  = '';

        $this->assertSame($expected, $actual, $message);

        // ==============================================
        $hashService = HashService::factory('sha512');

        $expected = \base64_decode('KHoPuJp/vfpbVThjaRjlN6W4MGXk/zMSaLeqoRXd4EepsPT7W4KGCPwLYyfxAFX3Y3sFjp4Nu55piQGj5t1GHA==', true);
        $actual   = $hashService->hmacBinary($base_message, $key, $count);
        $message  = '';

        $this->assertSame($expected, $actual, $message);

        // ==============================================
        $hashService = HashService::factory('sha256');
        $expected    = \base64_decode('CBstMy4QPs45o4A/++3CLp8u6PlLRzUe63wBruMjd1g=', true);
        $actual      = $hashService->stretchedHmacBinary($base_message, $key, $count);
        $message     = '';

        $this->assertSame($expected, $actual, $message);
    }

    #[Test]
    public function createStretchedHmacString(): void
    {
        // ==============================================
        $hashService = HashService::factory();

        $expected    = $hashService->createStretchedHmacString();
        $actual      = $hashService->createStretchedHmacString();
        $message     = '';

        $this->assertNotSame($expected, $actual, $message);

        // ==============================================
        $expected    = HashService::factory('sha256')->createStretchedHmacString();
        $actual      = HashService::factory('sha256')->createStretchedHmacString();
        $message     = '';

        $this->assertNotSame($expected, $actual, $message);

        // ==============================================
        $expected    = HashService::factory('sha256')->createStretchedHmacString();
        $actual      = HashService::factory('sha512')->createStretchedHmacString();
        $message     = '';

        $this->assertNotSame($expected, $actual, $message);

        // ==============================================
        $expected    = HashService::factory('sha256')->createStretchedHmacString(1);
        $actual      = HashService::factory('sha256')->createStretchedHmacString(1);
        $message     = '';

        $this->assertNotSame($expected, $actual, $message);

        // ==============================================
        $expected    = HashService::factory('sha256')->createStretchedHmacString(5);
        $actual      = HashService::factory('sha256')->createStretchedHmacString(5);
        $message     = '';

        $this->assertNotSame($expected, $actual, $message);

        // ==============================================
        $expected    = HashService::factory('sha256')->createStretchedHmacString(10);
        $actual      = HashService::factory('sha256')->createStretchedHmacString(10);
        $message     = '';

        $this->assertNotSame($expected, $actual, $message);
    }

    #[Test]
    public function createRandomHash(): void
    {
        $string            = 'test';
        $salt              = 'salt';
        $hmac_key          = 'key';

        // ==============================================
        $hashService = HashService::factory();

        $expected   = $hashService->createRandomHash($string, $salt, $hmac_key);
        $actual     = $hashService->createRandomHash($string, $salt, $hmac_key);
        $message    = '';

        $this->assertNotSame($expected, $actual, $message);

        // ==============================================
        $secret_key_length = 6;

        $hashService = HashService::factory();

        $expected   = $hashService->createRandomHash($string, $salt, $hmac_key, $secret_key_length);
        $actual     = $hashService->createRandomHash($string, $salt, $hmac_key, $secret_key_length);
        $message    = '';

        $this->assertNotSame($expected, $actual, $message);
    }

    #[Test]
    public function verifyRandomHash(): void
    {
        $string            = 'test';
        $salt              = 'salt';
        $hmac_key          = 'key';

        // ==============================================
        $hashService    = HashService::factory();

        $random_hash_1    = $hashService->createRandomHash($string, $salt, $hmac_key);
        $random_hash_2    = $hashService->createRandomHash($string, $salt, $hmac_key);

        $this->assertTrue($hashService->verifyRandomHash($random_hash_1, $string, $salt, $hmac_key));
        $this->assertTrue($hashService->verifyRandomHash($random_hash_2, $string, $salt, $hmac_key));
        $this->assertNotSame($random_hash_1, $random_hash_2);

        // ----------------------------------------------
        $random_hash_3    = $hashService->createRandomHash($string, $salt, $hmac_key, 6);

        $this->assertFalse($hashService->verifyRandomHash($random_hash_3, $string, $salt, $hmac_key));
        $this->assertNotSame($random_hash_1, $random_hash_3);
    }
}
