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
            $plaintext = '123456';
            $crypt = new Crypt();
            // 加密
            $entext = $crypt->encrypt($plaintext);
            // 解密
            $detext = $crypt->decrypt($entext);

            $message = 'a=aaa&b=bbb&c=ccc';
            // 签名
            $sign = $crypt->sign($message);
            // 签名验证
            $verify = $crypt->verify($message, $sign);

            var_dump(base64_encode($entext), $detext);
            var_dump(base64_encode($sign), $verify);
        } catch (CryptException $e) {
            echo $e->getMessage();
        } catch (\Exception $e) {
            echo $e->getMessage();
        }
    }
}
