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
            $crypt->loadKey($publicKey);
            $entext = $crypt->encrypt($plaintext);
            // 解密[私钥]
            $crypt->loadKey($privateKey);
            $detext = $crypt->decrypt($entext);
            var_dump(base64_encode($entext), $detext);

            //$crypt = new Crypt();
            //$keys = $crypt->createKey();
            //$privateKey = isset($keys['privateKey']) ? $keys['privateKey'] : null;
            //$publicKey = isset($keys['publicKey']) ? $keys['publicKey'] : null;

            $plaintext = '654321';
            // 加密[私钥]
            $crypt->loadKey($privateKey);
            $entext = $crypt->encryptByPrivateKey($plaintext);
            // 解密[公钥]
            $crypt->loadKey($publicKey);
            $detext = $crypt->decryptByPublicKey($entext);
            var_dump(base64_encode($entext), $detext);

            //$crypt = new Crypt();
            //$keys = $crypt->createKey();
            //$privateKey = isset($keys['privateKey']) ? $keys['privateKey'] : null;
            //$publicKey = isset($keys['publicKey']) ? $keys['publicKey'] : null;

            $message = 'a=aaa&b=bbb&c=ccc';
            // 签名[私钥]
            $crypt->loadKey($privateKey);
            $sign = $crypt->sign($message);
            // 签名验证[公钥]
            $crypt->loadKey($publicKey);
            $verify = $crypt->verify($message, $sign);

            var_dump(base64_encode($sign), $verify);

            // SM3
            $crypt = new Crypt('SM3');
            $plaintext = '123456';
            $entext = $crypt->encrypt($plaintext);
            var_dump($entext);

            // SM4
            $crypt = new Crypt('SM4');
            $secret = 'EZIwtOeuqf8BI/j3D0CjuQ==';//$crypt->createKey();
            $plaintext = '123456';
            $entext = $crypt->setIv($secret)->encrypt($plaintext);
            $detext = $crypt->setIv($secret)->decrypt($entext);
            var_dump($entext, $detext);
        } catch (CryptException $e) {
            echo $e->getMessage();
        } catch (\Exception $e) {
            echo $e->getMessage();
        }
    }
}
