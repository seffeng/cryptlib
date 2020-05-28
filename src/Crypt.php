<?php
/**
 * @link http://github.com/seffeng/
 * @copyright Copyright (c) 2020 seffeng
 */
namespace Seffeng\Cryptlib;

use Seffeng\Cryptlib\Exceptions\CryptException;

class Crypt
{
    /**
     *
     * @var mixed
     */
    protected $client;

    /**
     *
     * @var string
     */
    protected $privateKey;

    /**
     *
     * @var string
     */
    protected $publicKey;

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
        $this->client = $client;
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
        return [
            'privatekey' => '',
            'publickey' => '',
            'partialkey' => false
        ];
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
            return '';
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
            return '';
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
            return '';
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
            return true;
        } catch (\Exception $e) {
            throw new CryptException($e->getMessage());
        }
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
        $this->publicKey = $publicKey;
        return $this;
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
        return $this->publicKey;
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
        $this->privateKey = $privateKey;
        return $this;
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
        return $this->privateKey;
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
        return '';
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
        return '';
    }

    /**
     *
     * @author zxf
     * @date    2020年5月28日
     * @return number
     */
    public function getSize()
    {
        return 0;
    }
}
