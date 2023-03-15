<?php
/**
 * @link http://github.com/seffeng/
 * @copyright Copyright (c) 2020 seffeng
 */
namespace Seffeng\Cryptlib\Clients;

use Seffeng\Cryptlib\Interfaces\RSAInterface;
use Seffeng\Cryptlib\Exceptions\CryptException;

class RSA implements RSAInterface
{
    /**
     *
     * @var string
     */
    protected $comment;

    /**
     * [OPENSSL_PKCS1_PADDING, OPENSSL_SSLV23_PADDING, OPENSSL_NO_PADDING, OPENSSL_PKCS1_OAEP_PADDING]
     * @var integer
     */
    protected $encryptionMode = OPENSSL_PKCS1_PADDING;
    /**
     * [OPENSSL_PKCS1_PADDING, OPENSSL_NO_PADDING]
     * @var string
     */
    protected $privateEncryptionMode = OPENSSL_PKCS1_PADDING;
    /**
     * [OPENSSL_PKCS1_PADDING, OPENSSL_SSLV23_PADDING, OPENSSL_NO_PADDING, OPENSSL_PKCS1_OAEP_PADDING]
     * @var string
     */
    protected $publicEncryptionMode = OPENSSL_PKCS1_PADDING;

    /**
     * [OPENSSL_ALGO_SHA1, OPENSSL_ALGO_MD5, OPENSSL_ALGO_MD4, OPENSSL_ALGO_SHA224, OPENSSL_ALGO_SHA256, OPENSSL_ALGO_SHA384, OPENSSL_ALGO_SHA512, OPENSSL_ALGO_RMD160]
     * @var integer
     */
    protected $signatureMode = OPENSSL_ALGO_SHA1;

    /**
     *
     * @var string
     */
    protected $hash;

    /**
     *
     * @var string
     */
    protected $mgfHash;

    /**
     *
     * @var boolean
     */
    protected $password = false;

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
     * @var integer
     */
    protected $saltLength;

    /**
     *
     * @var integer
     */
    protected $privateKeyFormat;

    /**
     *
     * @var integer
     */
    protected $publicKeyFormat;

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::createKey()
     */
    public function createKey(int $bits = 1024, int $timeout = null, array $partial = [])
    {
        try {
            $privatekey = null;
            $publicKey = null;

            $configargs = [
                'config' => dirname(__DIR__) .'/openssl.cnf',
                'private_key_bits' => $bits,
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
            ];

            $resource = openssl_pkey_new($configargs);
            openssl_pkey_export($resource, $privatekey, null, $configargs);
            $privatekey = str_replace([
                '-----BEGIN PRIVATE KEY-----',
                '-----END PRIVATE KEY-----'
            ],[
                '-----BEGIN RSA PRIVATE KEY-----',
                '-----END RSA PRIVATE KEY-----'
            ], $privatekey);

            $publicDetails = openssl_pkey_get_details($resource);
            if (isset($publicDetails['key']) && $publicDetails['key']) {
                $publicKey = $publicDetails['key'];

                return [
                    'privateKey' => $privatekey,
                    'publicKey' => $publicKey,
                    'partialKey' => false
                ];
            }
            throw new CryptException('rsa keys created failed.');
        } catch (\Exception $e) {
            throw new CryptException($e->getMessage());
        }
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::loadKey()
     */
    public function loadKey($key, int $type = null)
    {
        try {
            is_file($key) && $key = file_get_contents($key);
            if (strpos($key, '-----BEGIN RSA PRIVATE KEY-----') !== false && strpos($key, '-----END RSA PRIVATE KEY-----') !== false && openssl_pkey_get_private($key)) {
                $this->setPrivateKey($key);
            } elseif (strpos($key, '-----BEGIN PRIVATE KEY-----') !== false && strpos($key, '-----END PRIVATE KEY-----') !== false && openssl_pkey_get_private($key)) {
                $this->setPrivateKey($key);
            } elseif (strpos($key, '-----BEGIN PUBLIC KEY-----') !== false && strpos($key, '-----END PUBLIC KEY-----') !== false && openssl_pkey_get_public($key)) {
                $this->setPublicKey($key);
            } elseif (strpos($key, '-----') === false) {
                $key = preg_replace("/[\s]+/", '', $key);
                $publicKey = '-----BEGIN PUBLIC KEY-----' . PHP_EOL. chunk_split($key, 64) . '-----END PUBLIC KEY-----';
                $privateKey = '-----BEGIN RSA PRIVATE KEY-----' . PHP_EOL. chunk_split($key, 64) . '-----END RSA PRIVATE KEY-----';
                if (openssl_pkey_get_public($publicKey)) {
                    $this->setPublicKey($publicKey);
                }
                if (openssl_pkey_get_private($privateKey)) {
                    $this->setPrivateKey($privateKey);
                }
            } else {
                throw new CryptException('invalid key.');
            }
            if ($this->getPrivateKey() || $this->getPublicKey()) {
                return true;
            }
            throw new CryptException('invalid key.');
        } catch (\Exception $e) {
            throw new CryptException($e->getMessage());
        }
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::encrypt()
     */
    public function encrypt(string $plaintext)
    {
        try {
            $crypted = null;
            openssl_public_encrypt($plaintext, $crypted, $this->getPublicKey(), $this->getPublicEncryptionMode());
            return $crypted;
        } catch (\Exception $e) {
            throw new CryptException($e->getMessage());
        }
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::encryptByPrivateKey()
     */
    public function encryptByPrivateKey(string $plaintext)
    {
        try {
            $crypted = null;
            openssl_private_encrypt($plaintext, $crypted, $this->getPrivateKey(), $this->getPrivateEncryptionMode());
            return $crypted;
        } catch (\Exception $e) {
            throw new CryptException($e->getMessage());
        }
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::decrypt()
     */
    public function decrypt(string $ciphertext)
    {
        try {
            $decrypted = null;
            openssl_private_decrypt($ciphertext, $decrypted, $this->getPrivateKey(), $this->getPublicEncryptionMode());
            return $decrypted;
        } catch (\Exception $e) {
            throw new CryptException($e->getMessage());
        }
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::decryptByPublicKey()
     */
    public function decryptByPublicKey(string $ciphertext)
    {
        try {
            $decrypted = null;
            openssl_public_decrypt($ciphertext, $decrypted, $this->getPublicKey(), $this->getPrivateEncryptionMode());
            return $decrypted;
        } catch (\Exception $e) {
            throw new CryptException($e->getMessage());
        }
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::sign()
     */
    public function sign(string $message)
    {
        try {
            $signature = null;
            openssl_sign($message, $signature, $this->getPrivateKey(), $this->getSignatureMode());
            return $signature;
        } catch (\Exception $e) {
            throw new CryptException($e->getMessage());
        }
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::verify()
     */
    public function verify(string $message, string $signature)
    {
        try {
            $verity = openssl_verify($message, $signature, $this->getPublicKey(), $this->getSignatureMode());
            if ($verity === 1) {
                return true;
            } elseif ($verity === 0) {
                return false;
            }
            throw new CryptException('verify error.');
        } catch (\Exception $e) {
            throw new CryptException($e->getMessage());
        }
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::setPublicKeyFormat()
     */
    public function setPublicKeyFormat(int $format)
    {
        $this->publicKeyFormat = $format;
        return $this;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::getPublicKeyFormat()
     */
    public function getPublicKeyFormat()
    {
        return $this->publicKeyFormat;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::setPublicKey()
     */
    public function setPublicKey(string $publicKey, int $type = null)
    {
        $this->publicKey = $publicKey;
        return $this;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::getPublicKey()
     */
    public function getPublicKey(int $type = null)
    {
        return $this->publicKey;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::setPrivateKeyFormat()
     */
    public function setPrivateKeyFormat(int $format)
    {
        $this->privateKeyFormat = $format;
        return $this;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::getPrivateKeyFormat()
     */
    public function getPrivateKeyFormat()
    {
        return $this->privateKeyFormat;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::setPrivateKey()
     */
    public function setPrivateKey(string $privateKey, int $type = null)
    {
        $this->privateKey = $privateKey;
        return $this;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::getPrivateKey()
     */
    public function getPrivateKey(int $type = null)
    {
        return $this->privateKey;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::setComment()
     */
    public function setComment(string $comment)
    {
        $this->comment = $comment;
        return $this;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::getComment()
     */
    public function getComment()
    {
        return $this->comment;
    }

    /**
     *
     * @author zxf
     * @date   2020年6月1日
     * @return array
     */
    protected function getEncryptionModeItems()
    {
        return [OPENSSL_PKCS1_PADDING, OPENSSL_SSLV23_PADDING, OPENSSL_NO_PADDING, OPENSSL_PKCS1_OAEP_PADDING];
    }

    /**
     *
     * @author zxf
     * @date   2020年6月1日
     * @return array
     */
    protected function getPublicEncryptionModeItems()
    {
        return [OPENSSL_PKCS1_PADDING, OPENSSL_SSLV23_PADDING, OPENSSL_NO_PADDING, OPENSSL_PKCS1_OAEP_PADDING];
    }

    /**
     *
     * @author zxf
     * @date   2020年6月1日
     * @return array
     */
    protected function getPrivateEncryptionModeItems()
    {
        return [OPENSSL_PKCS1_PADDING, OPENSSL_NO_PADDING];
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::setEncryptionMode()
     */
    public function setEncryptionMode(int $mode)
    {
        if (in_array($mode, $this->getEncryptionModeItems())) {
            $this->encryptionMode = $mode;
        }
        return $this;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::getEncryptionMode()
     */
    public function getEncryptionMode()
    {
        return $this->encryptionMode;
    }

    /**
     *
     * @author zxf
     * @date   2020年6月1日
     * @return integer
     */
    public function getPrivateEncryptionMode()
    {
        if (in_array($this->getEncryptionMode(), $this->getPrivateEncryptionModeItems())) {
            $this->privateEncryptionMode = $this->getEncryptionMode();
        }
        return $this->privateEncryptionMode;
    }

    /**
     *
     * @author zxf
     * @date   2020年6月1日
     * @return integer
     */
    public function getPublicEncryptionMode()
    {
        if (in_array($this->getEncryptionMode(), $this->getPublicEncryptionModeItems())) {
            $this->publicEncryptionMode = $this->getEncryptionMode();
        }
        return $this->publicEncryptionMode;
    }

    /**
     *
     * @author zxf
     * @date   2020年6月1日
     * @return array
     */
    protected function getSignatureModeItems()
    {
        return [OPENSSL_ALGO_SHA1, OPENSSL_ALGO_MD5, OPENSSL_ALGO_MD4, OPENSSL_ALGO_SHA224, OPENSSL_ALGO_SHA256, OPENSSL_ALGO_SHA384, OPENSSL_ALGO_SHA512, OPENSSL_ALGO_RMD160];
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::setSignatureMode()
     */
    public function setSignatureMode(int $mode)
    {
        if (in_array($mode,  $this->getSignatureModeItems())) {
            $this->signatureMode = $mode;
        }
        return $this;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::getSignatureMode()
     */
    public function getSignatureMode()
    {
        return $this->signatureMode;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::setHash()
     */
    public function setHash(string $hash)
    {
        $this->hash = $hash;
        return $this;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::getHash()
     */
    public function getHash()
    {
        return $this->hash;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::setMGFHash()
     */
    public function setMGFHash(string $hash)
    {
        $this->mgfHash = $hash;
        return $this;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::getMGFHash()
     */
    public function getMGFHash()
    {
        return $this->mgfHash;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::setPassword()
     */
    public function setPassword(bool $password = false)
    {
        $this->password = $password;
        return $this;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::getPassword()
     */
    public function getPassword()
    {
        return $this->password;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::setSaltLength()
     */
    public function setSaltLength(int $saltLength)
    {
        $this->saltLength = $saltLength;
        return $this;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::getSaltLength()
     */
    public function getSaltLength()
    {
        return $this->saltLength;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::getPublicKeyFingerprint()
     */
    public function getPublicKeyFingerprint(string $algorithm = 'md5')
    {
        return '';
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\RSAInterface::getSize()
     */
    public function getSize()
    {
        return 0;
    }
}
