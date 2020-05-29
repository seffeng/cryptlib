<?php
/**
 * @link http://github.com/seffeng/
 * @copyright Copyright (c) 2020 seffeng
 */
namespace Seffeng\Cryptlib\Clients;

use Seffeng\Cryptlib\Interfaces\CryptInterface;
use Seffeng\Cryptlib\Exceptions\CryptException;

class RSA implements CryptInterface
{
    /**
     *
     * @var string
     */
    protected $comment;

    /**
     *
     * @var integer
     */
    protected $encryptionMode;

    /**
     *
     * @var integer
     */
    protected $signatureMode;

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
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::createKey()
     */
    public function createKey(int $bits = 1024, int $timeout = null, array $partial = [])
    {
        try {
            $privatekey = null;
            $publicKey = null;

            $configargs = [
                'config' => dirname(__DIR__) .'/openssl.cnf',
                'private_key_bits' => $bits,
                'digest_alg' => 'sha256',
            ];

            $resource = openssl_pkey_new($configargs);
            openssl_pkey_export($resource, $privatekey, true, $configargs);

            $privatekey = str_replace([
                '-----BEGIN PRIVATE KEY-----',
                '-----END PRIVATE KEY-----',
            ], [
                '-----BEGIN RSA PRIVATE KEY-----',
                '-----END RSA PRIVATE KEY-----',
            ], $privatekey);

            $publicDetails = openssl_pkey_get_details($resource);
            if (isset($publicDetails['key']) && $publicDetails['key']) {
                $publicKey = str_replace([
                    '-----BEGIN PUBLIC KEY-----',
                    '-----END PUBLIC KEY-----',
                ], [
                    '-----BEGIN RSA PUBLIC KEY-----',
                    '-----END RSA PUBLIC KEY-----',
                ], $publicDetails['key']);

                return [
                    'privatekey' => $privatekey,
                    'publickey' => $publicKey,
                    'partialkey' => false
                ];
            }
            return null;
        } catch (\Exception $e) {
            throw new CryptException($e->getMessage());
        }
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::loadKey()
     */
    public function loadKey($key, int $type = null)
    {
        return true;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::encrypt()
     */
    public function encrypt(string $plaintext)
    {
        try {
            $crypted = null;
            openssl_public_encrypt($plaintext, $crypted, $this->getPublicKey());
            return $crypted;
        } catch (\Exception $e) {
            throw new CryptException($e->getMessage());
        }
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::decrypt()
     */
    public function decrypt(string $ciphertext)
    {
        try {
            $decrypted = null;
            openssl_private_decrypt($ciphertext, $decrypted, $this->getPrivateKey());
            return $decrypted;
        } catch (\Exception $e) {
            throw new CryptException($e->getMessage());
        }
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::sign()
     */
    public function sign(string $message)
    {
        return '123';
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::verify()
     */
    public function verify(string $message, string $signature)
    {
        return true;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::setPublicKeyFormat()
     */
    public function setPublicKeyFormat(int $format)
    {
        $this->publicKeyFormat = $format;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::getPublicKeyFormat()
     */
    public function getPublicKeyFormat()
    {
        return $this->publicKeyFormat;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::setPublicKey()
     */
    public function setPublicKey(string $publicKey, int $type = null)
    {
        $this->publicKey = $publicKey;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::getPublicKey()
     */
    public function getPublicKey(int $type = null)
    {
        return $this->publicKey;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::setPrivateKeyFormat()
     */
    public function setPrivateKeyFormat(int $format)
    {
        $this->privateKeyFormat = $format;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::getPrivateKeyFormat()
     */
    public function getPrivateKeyFormat()
    {
        return $this->privateKeyFormat;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::setPrivateKey()
     */
    public function setPrivateKey(string $privatekey, int $type = null)
    {
        $this->privateKey = $privatekey;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::getPrivateKey()
     */
    public function getPrivateKey(int $type = null)
    {
        return $this->privateKey;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::setComment()
     */
    public function setComment(string $comment)
    {
        $this->comment = $comment;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::getComment()
     */
    public function getComment()
    {
        return $this->comment;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::setEncryptionMode()
     */
    public function setEncryptionMode(int $mode)
    {
        $this->encryptionMode = $mode;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::getEncryptionMode()
     */
    public function getEncryptionMode()
    {
        return $this->encryptionMode;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::setSignatureMode()
     */
    public function setSignatureMode(int $mode)
    {
        $this->signatureMode = $mode;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::getSignatureMode()
     */
    public function getSignatureMode()
    {
        return $this->signatureMode;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::setHash()
     */
    public function setHash(string $hash)
    {
        $this->hash = $hash;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::getHash()
     */
    public function getHash()
    {
        return $this->hash;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::setMGFHash()
     */
    public function setMGFHash(string $hash)
    {
        $this->mgfHash = $hash;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::getMGFHash()
     */
    public function getMGFHash()
    {
        return $this->mgfHash;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::setPassword()
     */
    public function setPassword(bool $password = false)
    {
        $this->password = $password;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::getPassword()
     */
    public function getPassword()
    {
        return $this->password;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::setSaltLength()
     */
    public function setSaltLength(int $saltLength)
    {
        $this->saltLength = $saltLength;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::getSaltLength()
     */
    public function getSaltLength()
    {
        return $this->saltLength;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::getPublicKeyFingerprint()
     */
    public function getPublicKeyFingerprint(string $algorithm = 'md5')
    {
        return '';
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\CryptInterface::getSize()
     */
    public function getSize()
    {
        return 0;
    }
}
