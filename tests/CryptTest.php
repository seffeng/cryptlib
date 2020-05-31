<?php  declare(strict_types=1);

namespace Seffeng\Cryptlib\Tests;

use PHPUnit\Framework\TestCase;
use Seffeng\Cryptlib\Crypt;
use Seffeng\Cryptlib\Exceptions\CryptException;

class CryptTest extends TestCase
{
    public function testCrypt()
    {
        try {
            $crypt = new Crypt();
            $keys = $crypt->createKey();
            $privateKey = isset($keys['privateKey']) ? $keys['privateKey'] : null;
            $publicKey = isset($keys['publicKey']) ? $keys['publicKey'] : null;
            //$crypt->setPrivateKey($privateKey)->setPublicKey($publicKey);

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
        } catch (CryptException $e) {
            echo $e->getMessage();
        } catch (\Exception $e) {
            echo $e->getMessage();
        }
    }
}
