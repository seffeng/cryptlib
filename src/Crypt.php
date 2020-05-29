<?php
/**
 * @link http://github.com/seffeng/
 * @copyright Copyright (c) 2020 seffeng
 */
namespace Seffeng\Cryptlib;

use Seffeng\Cryptlib\Exceptions\CryptException;
use Seffeng\Cryptlib\Interfaces\CryptInterface;

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
    protected $allowClients = ['RSA'];

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
     * @date   2020年5月20日
     * @param  int $bits
     * @param  int $timeout
     * @param  array $partial
     * @return array
     */
    public function createKey(int $bits = 1024, int $timeout = null, array $partial = [])
    {
        try {
            return $this->getClient()->createKey($bits, $timeout, $partial);
        } catch (\Exception $e) {
            throw new CryptException($e->getMessage());
        }
    }

    /**
     *
     * @author zxf
     * @date    2020年5月28日
     * @param  string $plaintext
     * @throws CryptException
     * @return string
     */
    public function encrypt(string $plaintext)
    {
        try {
            return $this->getClient()->encrypt($plaintext);
        } catch (\Exception $e) {
            throw new CryptException($e->getMessage());
        }
    }

    /**
     *
     * @author zxf
     * @date    2020年5月28日
     * @param  string $ciphertext
     * @throws CryptException
     * @return string
     */
    public function decrypt(string $ciphertext)
    {
        try {
            return $this->getClient()->decrypt($ciphertext);
        } catch (\Exception $e) {
            throw new CryptException($e->getMessage());
        }
    }

    /**
     *
     * @author zxf
     * @date    2020年5月28日
     * @param  string $message
     * @throws CryptException
     * @return string
     */
    public function sign(string $message)
    {
        try {
            return $this->getClient()->sign($message);
        } catch (\Exception $e) {
            throw new CryptException($e->getMessage());
        }
    }

    /**
     *
     * @author zxf
     * @date    2020年5月28日
     * @param  string $message
     * @param  string $signature
     * @throws CryptException
     * @return boolean
     */
    public function verify(string $message, string $signature)
    {
        try {
            return $this->getClient()->verify($message, $signature);
        } catch (\Exception $e) {
            throw new CryptException($e->getMessage());
        }
    }

    /**
     *
     * @author zxf
     * @date    2020年5月29日
     * @param  string|array $key
     * @param  integer $type optional
     * @return boolean
     */
    public function loadKey($key, int $type = null)
    {
        try {
            return $this->getClient()->loadKey($key, $type);
        } catch (\Exception $e) {
            return false;
        }
    }

    /**
     *
     * @author zxf
     * @date    2020年5月28日
     * @param  integer $format
     * @return \Seffeng\Cryptlib\Crypt
     */
    public function setPublicKeyFormat(int $format)
    {
        $this->getClient()->setPublicKeyFormat($format);
        return $this;
    }

    /**
     *
     * @author zxf
     * @date    2020年5月28日
     * @param  string $publicKey
     * @return \Seffeng\Cryptlib\Crypt
     */
    public function setPublicKey(string $publicKey = null)
    {
        $this->getClient()->setPublicKey($publicKey);
        return $this;
    }

    /**
     *
     * @author zxf
     * @date    2020年5月28日
     * @return string
     */
    public function getPublicKey()
    {
        return $this->getClient()->getPublicKey();
    }

    /**
     *
     * @author zxf
     * @date    2020年5月28日
     * @param  integer $format
     * @return \Seffeng\Cryptlib\Crypt
     */
    public function setPrivateKeyFormat(int $format)
    {
        $this->getClient()->setPrivateKeyFormat($format);
        return $this;
    }

    /**
     *
     * @author zxf
     * @date    2020年5月28日
     * @param  string $privateKey
     * @return \Seffeng\Cryptlib\Crypt
     */
    public function setPrivateKey(string $privateKey = null)
    {
        $this->getClient()->setPrivateKey($privateKey);
        return $this;
    }

    /**
     *
     * @author zxf
     * @date    2020年5月28日
     * @return string
     */
    public function getPrivateKey()
    {
        return $this->getClient()->getPrivateKey();
    }

    /**
     *
     * @author zxf
     * @date    2020年5月28日
     * @param  string $comment
     * @return \Seffeng\Cryptlib\Crypt
     */
    public function setComment(string $comment)
    {
        $this->getClient()->setComment($comment);
        return $this;
    }

    /**
     *
     * @author zxf
     * @date    2020年5月28日
     * @return string
     */
    public function getComment()
    {
        return $this->getClient()->getComment();
    }

    /**
     *
     * @author zxf
     * @date    2020年5月28日
     * @param  int $mode
     * @return \Seffeng\Cryptlib\Crypt
     */
    public function setEncryptionMode(int $mode)
    {
        $this->getClient()->setEncryptionMode($mode);
        return $this;
    }

    /**
     *
     * @author zxf
     * @date    2020年5月28日
     * @param int $mode
     * @return \Seffeng\Cryptlib\Crypt
     */
    public function setSignatureMode(int $mode)
    {
        $this->getClient()->setSignatureMode($mode);
        return $this;
    }

    /**
     *
     * @author zxf
     * @date    2020年5月28日
     * @param  string $hash
     * @return \Seffeng\Cryptlib\Crypt
     */
    public function setHash(string $hash)
    {
        $this->getClient()->setHash($hash);
        return $this;
    }

    /**
     *
     * @author zxf
     * @date    2020年5月28日
     * @param  string $hash
     * @return \Seffeng\Cryptlib\Crypt
     */
    public function setMGFHash(string $hash)
    {
        $this->getClient()->setMGFHash($hash);
        return $this;
    }

    /**
     *
     * @author zxf
     * @date    2020年5月28日
     * @param  boolean $password
     * @return \Seffeng\Cryptlib\Crypt
     */
    public function setPassword(bool $password = false)
    {
        $this->getClient()->setPassword($password);
        return $this;
    }

    /**
     *
     * @author zxf
     * @date    2020年5月28日
     * @param  int $saltLength
     * @return \Seffeng\Cryptlib\Crypt
     */
    public function setSaltLength(int $saltLength)
    {
        $this->getClient()->setSaltLength($saltLength);
        return $this;
    }

    /**
     *
     * @author zxf
     * @date    2020年5月28日
     * @param  string $algorithm string $algorithm The hashing algorithm to be used. Valid options are 'md5' and 'sha256'.
     * @return mixed|boolean|string
     */
    public function getPublicKeyFingerprint(string $algorithm = 'md5')
    {
        return $this->getClient()->getPublicKeyFingerprint();
    }

    /**
     *
     * @author zxf
     * @date    2020年5月28日
     * @return number
     */
    public function getSize()
    {
        return $this->getClient()->getSize();
    }

    /**
     *
     * @author zxf
     * @date   2020年5月29日
     * @return CryptInterface
     */
    public function getClient()
    {
        return $this->client;
    }
}
