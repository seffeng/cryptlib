<?php
/**
 * @link http://github.com/seffeng/
 * @copyright Copyright (c) 2020 seffeng
 */
namespace Seffeng\Cryptlib\Interfaces;

use Seffeng\Cryptlib\Exceptions\CryptException;

interface RSAInterface
{
    /**
     *
     * @author zxf
     * @date    2020年5月29日
     * @param  int $bits
     * @param  int $timeout
     * @param  array $partial
     * @throws CryptException
     * @return array
     */
    public function createKey(int $bits = 1024, int $timeout = null, array $partial = []);

    /**
     *
     * @author zxf
     * @date    2020年5月29日
     * @param  string|resource $key
     * @param  int $type
     * @throws CryptException
     * @return boolean
     */
    public function loadKey($key, int $type = null);

    /**
     *
     * @author zxf
     * @date    2020年5月29日
     * @param  string $plaintext
     * @throws CryptException
     * @return string
     */
    public function encrypt(string $plaintext);

    /**
     *
     * @author zxf
     * @date    2020年5月30日
     * @param  string $plaintext
     * @throws CryptException
     * @return string
     */
    public function encryptByPrivateKey(string $plaintext);

    /**
     *
     * @author zxf
     * @date    2020年5月29日
     * @param  string $ciphertext
     * @throws CryptException
     * @return string
     */
    public function decrypt(string $ciphertext);

    /**
     *
     * @author zxf
     * @date    2020年5月30日
     * @param  string $ciphertext
     * @throws CryptException
     * @return string
     */
    public function decryptByPublicKey(string $ciphertext);

    /**
     *
     * @author zxf
     * @date    2020年5月29日
     * @param  string $message
     * @throws CryptException
     * @return string
     */
    public function sign(string $message);

    /**
     *
     * @author zxf
     * @date    2020年5月29日
     * @param  string $message
     * @param  string $signature
     * @throws CryptException
     * @return boolean
     */
    public function verify(string $message, string $signature);

    /**
     *
     * @author zxf
     * @date    2020年5月29日
     * @param  integer $format
     */
    public function setPublicKeyFormat(int $format);

    /**
     *
     * @author zxf
     * @date   2020年5月29日
     * @return integer
     */
    public function getPublicKeyFormat();

    /**
     *
     * @author zxf
     * @date   2020年5月29日
     * @param string $publicKey
     * @param integer $type optional
     */
    public function setPublicKey(string $publicKey, int $type = null);

    /**
     *
     * @author zxf
     * @date   2020年5月29日
     * @param integer $type optional
     * @return string
     */
    public function getPublicKey(int $type = null);

    /**
     *
     * @author zxf
     * @date    2020年5月29日
     * @param  integer $format
     */
    public function setPrivateKeyFormat(int $format);

    /**
     *
     * @author zxf
     * @date   2020年5月29日
     * @return integer
     */
    public function getPrivateKeyFormat();

    /**
     *
     * @author zxf
     * @date   2020年5月29日
     * @param string $privateKey
     * @param integer $type optional
     */
    public function setPrivateKey(string $privateKey, int $type = null);

    /**
     *
     * @author zxf
     * @date   2020年5月29日
     * @param integer $type optional
     * @return string
     */
    public function getPrivateKey(int $type = null);

    /**
     *
     * @author zxf
     * @date   2020年5月29日
     * @param string $comment
     */
    public function setComment(string $comment);

    /**
     *
     * @author zxf
     * @date   2020年5月29日
     * @return string
     */
    public function getComment();

    /**
     *
     * @author zxf
     * @date   2020年5月29日
     * @param int $mode
     */
    public function setEncryptionMode(int $mode);

    /**
     *
     * @author zxf
     * @date    2020年5月29日
     * @return integer
     */
    public function getEncryptionMode();

    /**
     *
     * @author zxf
     * @date   2020年5月29日
     * @param int $mode
     */
    public function setSignatureMode(int $mode);

    /**
     *
     * @author zxf
     * @date   2020年5月29日
     * @return integer
     */
    public function getSignatureMode();

    /**
     *
     * @author zxf
     * @date   2020年5月29日
     * @param string $hash
     */
    public function setHash(string $hash);

    /**
     *
     * @author zxf
     * @date   2020年5月29日
     * @return string
     */
    public function getHash();

    /**
     *
     * @author zxf
     * @date   2020年5月29日
     * @param string $hash
     */
    public function setMGFHash(string $hash);

    /**
     *
     * @author zxf
     * @date   2020年5月29日
     * @return string
     */
    public function getMGFHash();

    /**
     *
     * @author zxf
     * @date   2020年5月29日
     * @param bool $password
     */
    public function setPassword(bool $password = false);

    /**
     *
     * @author zxf
     * @date    2020年5月29日
     * @return boolean
     */
    public function getPassword();

    /**
     *
     * @author zxf
     * @date   2020年5月29日
     * @param int $saltLength
     */
    public function setSaltLength(int $saltLength);

    /**
     *
     * @author zxf
     * @date    2020年5月29日
     * @return integer
     */
    public function getSaltLength();

    /**
     *
     * @author zxf
     * @date    2020年5月29日
     * @param  string $algorithm
     * @return string|boolean
     */
    public function getPublicKeyFingerprint(string $algorithm = 'md5');

    /**
     *
     * @author zxf
     * @date    2020年5月29日
     * @return integer
     */
    public function getSize();

}
