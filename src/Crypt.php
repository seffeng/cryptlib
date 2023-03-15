<?php
/**
 * @link http://github.com/seffeng/
 * @copyright Copyright (c) 2020 seffeng
 */
namespace Seffeng\Cryptlib;

use Seffeng\Cryptlib\Exceptions\CryptException;

/**
 *
 * @method array createKey(int $bits = 1024, int $timeout = null, array $partial = [])
 * @method string createKey(&$strong = null)
 * @method boolean loadKey($key, int $type = null)
 * @method string encrypt(string $plaintext)
 * @method string encryptByPrivateKey(string $plaintext)
 * @method string decrypt(string $ciphertext)
 * @method string decryptByPublicKey(string $ciphertext)
 * @method string sign(string $message)
 * @method boolean verify(string $message, string $signature)
 * @method mixed setPublicKeyFormat(int $format)
 * @method integer getPublicKeyFormat()
 * @method mixed setPublicKey(string $publicKey, int $type = null)
 * @method string getPublicKey(int $type = null)
 * @method mixed setPrivateKeyFormat(int $format)
 * @method integer getPrivateKeyFormat()
 * @method mixed setPrivateKey(string $privateKey, int $type = null)
 * @method string getPrivateKey(int $type = null)
 * @method mixed setComment(string $comment)
 * @method string getComment()
 * @method mixed setEncryptionMode(int $mode)
 * @method integer getEncryptionMode()
 * @method mixed setSignatureMode(int $mode)
 * @method integer getSignatureMode()
 * @method mixed setHash(string $hash)
 * @method string getHash()
 * @method mixed setMGFHash(string $hash)
 * @method string getMGFHash()
 * @method mixed setPassword(bool|string $password = false)
 * @method string|boolean getPassword()
 * @method mixed setSaltLength(int $saltLength)
 * @method integer getSaltLength()
 * @method string|boolean getPublicKeyFingerprint(string $algorithm = 'md5')
 * @method integer getSize()
 * @method \Seffeng\Cryptlib\Clients\SM3|\Seffeng\Cryptlib\Clients\SM4 setAlgo(string $algo)
 * @method string getAlgo()
 * @method \Seffeng\Cryptlib\Clients\SM4 setLength(int $length)
 * @method integer getLength()
 * @method \Seffeng\Cryptlib\Clients\SM4 setIv(string $iv)
 * @method string getIv()
 * @method \Seffeng\Cryptlib\Clients\SM4 setOptions(int $options)
 * @method integer getOptions()
 * @method \Seffeng\Cryptlib\Clients\SM4 setAdd(string $add)
 * @method string getAdd()
 * @method \Seffeng\Cryptlib\Clients\SM4 setTag(string $tag)
 * @method string getTag()
 * @method \Seffeng\Cryptlib\Clients\SM4 setTagLength(int $tagLength)
 * @method integer getTagLength()
 * @method array getCipherMethods()
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
