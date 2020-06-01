## cryptlib

### 安装

```shell
# 安装
$ composer require seffeng/cryptlib
```

### 目录说明

```
├─src
│  │  Crypt.php
│  │  openssl.cnf
│  ├─Clients
│  │    RSA.php
│  ├─Exceptions
│  │    CryptException.php
│  └─Interfaces
│       CryptInterface.php
└─tests
    CryptTest.php
```

### 方法

```php
$crypt = new Crypt();
# 1、生成 KEY，保存秘钥对
$keys = $crypt->createKey();
```

```php
# 1、加密
$crypt->loadKey($publicKey);
$crypt->encrypt($plaintext);

# 2、解密
$crypt->loadKey($privateKey);
$crypt->decrypt($entext);

# 3、签名
$crypt->loadKey($privateKey);
$crypt->sign($message);

# 4、签名验证
$crypt->loadKey($publicKey);
$crypt->verify($message, $sign);
```

### 示例

```php
/**
 * SiteController
 */
use Seffeng\Cryptlib\Crypt;

class SiteController extends Controller
{
    public function index()
    {
        $crypt = new Crypt();
        // 生成 KEY
        $keys = $crypt->createKey();
        $privateKey = isset($keys['privateKey']) ? $keys['privateKey'] : null;
        $publicKey = isset($keys['publicKey']) ? $keys['publicKey'] : null;
        //$crypt->setPrivateKey($privateKey)->setPublicKey($publicKey);
        $crypt->setEncryptionMode(1);

        $plaintext = '123456';
        // 加密[公钥]
        $entext = $crypt->loadKey($publicKey)->encrypt($plaintext);
        // 解密[私钥]
        $detext = $crypt->loadKey($privateKey)->decrypt($entext);
        var_dump(base64_encode($entext), $detext);

        //$crypt = new Crypt();
        //$keys = $crypt->createKey();
        //$privateKey = isset($keys['privateKey']) ? $keys['privateKey'] : null;
        //$publicKey = isset($keys['publicKey']) ? $keys['publicKey'] : null;

        $plaintext = '654321';
        // 加密[私钥]
        $entext = $crypt->loadKey($privateKey)->encryptByPrivateKey($plaintext);
        // 解密[公钥]
        $detext = $crypt->loadKey($publicKey)->decryptByPublicKey($entext);
        var_dump(base64_encode($entext), $detext);

        //$crypt = new Crypt();
        //$keys = $crypt->createKey();
        //$privateKey = isset($keys['privateKey']) ? $keys['privateKey'] : null;
        //$publicKey = isset($keys['publicKey']) ? $keys['publicKey'] : null;

        $message = 'a=aaa&b=bbb&c=ccc';
        // 签名[私钥]
        $sign = $crypt->loadKey($privateKey)->sign($message);
        // 签名验证[公钥]
        $verify = $crypt->loadKey($publicKey)->verify($message, $sign);

        var_dump(base64_encode($sign), $verify);
    }
}
```

### 备注

无