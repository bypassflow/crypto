# baypassflow crypt

bypassflow cryptはPHP8.4以降で利用できる暗号・ハッシュライブラリです。

一般的なレインボーテーブル攻撃に対して強い抗堪性を持つハッシュ・暗号化処理を提供します。

攻撃者に対して値の解析そのものを無駄打ちさせる事で、情報が価値を失うまでの十分な期間の安全を確保します。

また、一般的なハッシュやOpenSSLを利用した暗号化も提供します。

特にOpenSSLを利用した暗号化を扱う際に保存が必須となる情報を簡単に取得できるので、OpenSSLを利用した暗号化を容易に導入する事ができます。

## 導入方法

`composer require baypassflow/crypt`としてインストールできます。

[Packagist](https://packagist.org/packages/baypassflow/crypt)

## 主な機能

### ランダムハッシュ

`HashService::createRandomHash()`を用いて**データ、ソルト、HMACキーが同じであっても常に異なるハッシュ値**を返します。

これにより一般的なレインボーテーブル攻撃を無効化します。

生成されたハッシュは `HashService::verifyRandomHash()` で整合性の確認を行えます。

実行例：

```php
use bypassflow\crypt\HashService;

$string_1   = 'string1';
$salt_1     = 'salt1';
$hmac_key_1 = 'hmac_key1';

$string_2   = 'string2';
$salt_2     = 'salt2';
$hmac_key_2 = 'hmac_key2';

$hashService = HashService::factory();

$hash_same_1 = $hashService->createRandomHash(
    $string_1,
    $salt_1,
    $hmac_key_1,
);

$hash_same_2 = $hashService->createRandomHash(
    $string_1,
    $salt_1,
    $hmac_key_1,
);

$hash_salt = $hashService->createRandomHash(
    $string_1,
    $salt_2,
    $hmac_key_1,
);

$hash_hmac_key = $hashService->createRandomHash(
    $string_1,
    $salt_1,
    $hmac_key_2,
);

$hash_string_2 = $hashService->createRandomHash(
    $string_2,
    $salt_1,
    $hmac_key_1,
);

\var_dump(
    [
        $hash_same_1,                   // string(69) "ef48dd9460ff27afe437b6e269c00fa270ed1707a17e310484f3d47b354baa98f17d9"
        $hashService->verifyRandomHash( // bool(true)
            $hash_same_1,
            $string_1,
            $salt_1,
            $hmac_key_1,
        ),
    ],
    [
        // hash_same_1と異なるハッシュが出力されているが、verifyに成功している事に注目
        $hash_same_2,                   // string(69) "182cb5253686f281ad0276c0165f5e10662ee1fc515fddfac4588c54df27cac4e5bb4"
        $hashService->verifyRandomHash( // bool(true)
            $hash_same_2,
            $string_1,
            $salt_1,
            $hmac_key_1,
        ),
    ],
    [
        // 生成時のソルトが異なるのでverify失敗
        $hash_salt,                     // string(69) "8401dfd573c999831b96d21785765a6a253d60edcdea910c73629a969b328475b1511"
        $hashService->verifyRandomHash( // bool(false)
            $hash_salt,
            $string_1,
            $salt_1,
            $hmac_key_1,
        ),
    ],
    [
        // 生成時のHMACキーが異なるのでverify失敗
        $hash_hmac_key,                 // string(69) "b449f1d77ff5bca9cfc58017c052e61b98d5a93fb484a36914a854a3bec74be001012"
        $hashService->verifyRandomHash( // bool(false)
            $hash_salt,
            $string_1,
            $salt_1,
            $hmac_key_1,
        ),
    ],
    [
        // 生成時の文字列が異なるのでverify失敗
        $hash_string_2,                 // string(69) "c76f044bd2905df829d1b0d9b640ba99afdc81c9fbc9fd2f4182af1bb17c1a342de25"
        $hashService->verifyRandomHash( // bool(false)
            $hash_string_2,
            $string_1,
            $salt_1,
            $hmac_key_1,
        ),
    ],
);
```

### ランダム暗号化

`RandomCryptService::encrypt()`を用いて**データ、パスワード、ソルト、HMACキーが同じであっても常に異なる暗号化テキスト**を返します。

暗号化文字列として破綻しているようにみえる文字列を返すため、実装を含めた全ての情報が揃わない限り、事実上、復号は不可能です。

生成された暗号化テキストは `RandomCryptService::decrypt()` で復号できます。

実行例：

```php
use bypassflow\crypt\CryptService;
use bypassflow\crypt\HashService;
use bypassflow\crypt\RandomCryptService;

$text       = 'text';
$password   = 'pass';
$salt       = 'salt';
$hmac_key   = 'key';

// ==============================================
$randomCryptService = RandomCryptService::factory(
    CryptService::factory(),
    HashService::factory(),
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

\var_dump(
    // 同じデータで異なる暗号化結果が出力されているが、共に正しく復号出来ている
    $cipherResult1->cipher_text,        // string(94) "bW9PVmUyZjVMwd1A2WVBGVjFCdlBnZnh1V1lYZ1pkcXd3QWpYYUtIeTVwSW95REZvVHF6c0w0R3hJRXRGcW9sdVN0ZA==="
    $randomCryptService->decrypt(       // string(4) "text"
        $cipherResult1->cipher_text,
        $password,
        $salt,
        $hmac_key,
    )->text,
    $cipherResult2->cipher_text,        // string(94) "aW5IU2Y1ND3RLTWI1cVRFSmM2d2lkRGRUY1B4SEZQaWxJaERGZXdNRXowUnlYQnRpR25JaW1hRHRGVHNFU01QRVQwMA==="
    $randomCryptService->decrypt(       // string(4) "text"
        $cipherResult2->cipher_text,
        $password,
        $salt,
        $hmac_key,
    )->text,
);
```

### ハッシュ

`HashService::factory()->stretchedHmacString($string, $key, $count)` とすることで十分にストレッチされたハッシュ文字列を容易く得る事が出来ます。

### OpenSSLを利用した暗号化

`CryptService::factory()->encrypt($text, $passphrase)`とすることで容易にOpenSSLを利用した暗号化を扱えます。

復号も`CryptService::factory()->decrypt($cipher_text, $passphrase)`とすることで容易に行えます。

また、OpenSSLを利用した暗号化でありがちなIVなどの暗号化コンテキストの保存も次の形で容易に行う事ができます。

暗号化
```php
use bypassflow\crypt\CryptService;

$encryptResult = CryptService::factory()->encrypt($text, $passphrase);

$cipher_text    = $encryptResult->cipher_text;  // 暗号化された文字列

$crypto_context = $$encryptResult->cryptConfig->crypto_context; // これを保存する
```

復号
```php
use bypassflow\crypt\CryptService;

$cryptService   = CryptService::factoryFromCryptContext($crypto_context);   // 暗号化時に保存した$crypto_contextを引数として渡す

$decryptResult  = $cryptService->decrypt($cipher_text, $passphrase);

$text   = $decryptResult->text; // 簡単確実に復号できた
```
