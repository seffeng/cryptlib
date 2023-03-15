<?php
/**
 * @link http://github.com/seffeng/
 * @copyright Copyright (c) 2020 seffeng
 */
namespace Seffeng\Cryptlib;

use Seffeng\Cryptlib\Exceptions\CryptException;

/**
 *
 * @method static|array createKey(int $bits = 1024, int $timeout = null, array $partial = [])
 * @method static|string createKey(&$strong = null)
 * @method static|boolean loadKey($key, int $type = null)
 * @method static|string encrypt(string $plaintext)
 * @method static|string encryptByPrivateKey(string $plaintext)
 * @method static|string decrypt(string $ciphertext)
 * @method static|string decryptByPublicKey(string $ciphertext)
 * @method static|string sign(string $message)
 * @method static|boolean verify(string $message, string $signature)
 * @method static|mixed setPublicKeyFormat(int $format)
 * @method static|integer getPublicKeyFormat()
 * @method static|mixed setPublicKey(string $publicKey, int $type = null)
 * @method static|string getPublicKey(int $type = null)
 * @method static|mixed setPrivateKeyFormat(int $format)
 * @method static|integer getPrivateKeyFormat()
 * @method static|mixed setPrivateKey(string $privateKey, int $type = null)
 * @method static|string getPrivateKey(int $type = null)
 * @method static|mixed setComment(string $comment)
 * @method static|string getComment()
 * @method static|mixed setEncryptionMode(int $mode)
 * @method static|integer getEncryptionMode()
 * @method static|mixed setSignatureMode(int $mode)
 * @method static|integer getSignatureMode()
 * @method static|mixed setHash(string $hash)
 * @method static|string getHash()
 * @method static|mixed setMGFHash(string $hash)
 * @method static|string getMGFHash()
 * @method static|mixed setPassword(bool|string $password = false)
 * @method static|string|boolean getPassword()
 * @method static|mixed setSaltLength(int $saltLength)
 * @method static|integer getSaltLength()
 * @method static|string|boolean getPublicKeyFingerprint(string $algorithm = 'md5')
 * @method static|integer getSize()
 * @method static|\Seffeng\Cryptlib\Clients\SM3|\Seffeng\Cryptlib\Clients\SM4 setAlgo(string $algo)
 * @method static|string getAlgo()
 * @method static|\Seffeng\Cryptlib\Clients\SM4 setLength(int $length)
 * @method static|integer getLength()
 * @method static|\Seffeng\Cryptlib\Clients\SM4 setIv(string $iv)
 * @method static|string getIv()
 * @method static|\Seffeng\Cryptlib\Clients\SM4 setOptions(int $options)
 * @method static|integer getOptions()
 * @method static|\Seffeng\Cryptlib\Clients\SM4 setAdd(string $add)
 * @method static|string getAdd()
 * @method static|\Seffeng\Cryptlib\Clients\SM4 setTag(string $tag)
 * @method static|string getTag()
 * @method static|\Seffeng\Cryptlib\Clients\SM4 setTagLength(int $tagLength)
 * @method static|integer getTagLength()
 * @method static|array getCipherMethods()
 */
class Crypt
{
    /**
     *
     * @var mixed
     */
    protected $client;

    /**
     *
     * @var array
     */
    protected $allowClients = ['RSA', 'SM3', 'SM4'];

    /**
     *
     * @var string
     */
    protected $defaultClient = 'RSA';

    /**
     *
     * @author zxf
     * @date    2020年5月28日
     */
    public function __construct(string $client = null)
    {
        if (!extension_loaded('openssl')) {
            throw new CryptException('openssl extension must be loaded.');
        }
        if (!in_array($client, $this->allowClients)) {
            $client = $this->defaultClient;
        }
        $class = '\\Seffeng\\Cryptlib\\Clients\\'. $client;
        $this->client = new $class;
    }

    /**
     *
     * @author zxf
     * @date   2020年5月29日
     * @return \Seffeng\Cryptlib\Clients\RSA|\Seffeng\Cryptlib\Clients\SM3|\Seffeng\Cryptlib\Clients\SM4
     */
    public function getClient()
    {
        return $this->client;
    }

    /**
     *
     * @author zxf
     * @date   2023-03-15
     * @param  mixed  $method
     * @param  mixed $parameters
     * @throws CryptException
     * @return mixed
     */
    public function __call($method, $parameters)
    {
        if (method_exists($this->getClient(), $method)) {
            return $this->getClient()->{$method}(...$parameters);
        } else {
            throw new CryptException('方法｛' . $method . '｝不存在！');
        }
    }
}
