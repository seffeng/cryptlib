<?php
/**
 * @link http://github.com/seffeng/
 * @copyright Copyright (c) 2023 seffeng
 */
namespace Seffeng\Cryptlib\Clients;

use Seffeng\Cryptlib\Interfaces\SM4Interface;

class SM4 implements SM4Interface
{
    /**
     * @var string
     */
    protected $algo = 'sm4';

    /**
     * @var string
     */
    protected $password = '';

    /**
     * @var integer [OPENSSL_RAW_DATA, OPENSSL_ZERO_PADDING]
     */
    protected $options = 0;

    /**
     * 秘钥长度
     * @var integer
     */
    protected $length;

    /**
     * @var string
     */
    protected $tag = '';

    /**
     * @var integer
     */
    protected $tagLength = 16;

    /**
     * @var string
     */
    protected $add = '';

    /**
     * @var    string
     */
    protected $iv;

    /**
     * @var array
     */
    protected $cipherMethods = ['sm4', 'sm4-cbc', 'sm4-cfb', 'sm4-ctr', 'sm4-ecb', 'sm4-ofb'];

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\SM4Interface::encrypt()
     */
    public function encrypt(string $plaintext)
    {
        return openssl_encrypt($plaintext, $this->getAlgo(), $this->getPassword(), $this->getOptions(), $this->getIv());
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\SM4Interface::decrypt()
     */
    public function decrypt(string $ciphertext)
    {
        return openssl_decrypt($ciphertext, $this->getAlgo(), $this->getPassword(), $this->getOptions(), $this->getIv());
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\SM4Interface::createKey()
     */
    public function createKey(&$strong = null)
    {
        is_null($this->getLength()) && $this->setLength(openssl_cipher_iv_length($this->getAlgo()));
        return base64_encode(openssl_random_pseudo_bytes($this->getLength(), $strong));
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\SM4Interface::setLength()
     */
    public function setLength(int $length)
    {
        $this->length = $length;
        return $this;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\SM4Interface::getLength()
     */
    public function getLength()
    {
        return $this->length;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\SM4Interface::setIv()
     */
    public function setIv(string $iv)
    {
        $this->iv = $iv;
        return $this;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\SM4Interface::getIv()
     */
    public function getIv()
    {
        return base64_decode($this->iv);
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\SM4Interface::setAlgo()
     */
    public function setAlgo(string $algo)
    {
        $algo = strtolower($algo);
        if (in_array($algo, $this->getCipherMethods())) {
            $this->algo = $algo;
        }
        return $this;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\SM4Interface::getAlgo()
     */
    public function getAlgo()
    {
        return $this->algo;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\SM4Interface::setPassword()
     */
    public function setPassword(string $password)
    {
        $this->password = $password;
        return $this;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\SM4Interface::getPassword()
     */
    public function getPassword()
    {
        return $this->password;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\SM4Interface::setOptions()
     */
    public function setOptions(int $options)
    {
        $this->options = $options;
        return $this;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\SM4Interface::getOptions()
     */
    public function getOptions()
    {
        return $this->options;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\SM4Interface::setAdd()
     */
    public function setAdd(string $add)
    {
        $this->add = $add;
        return $this;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\SM4Interface::getAdd()
     */
    public function getAdd()
    {
        return $this->add;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\SM4Interface::setTag()
     */
    public function setTag(string $tag)
    {
        $this->tag = $tag;
        return $this;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\SM4Interface::getTag()
     */
    public function getTag()
    {
        return $this->tag;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\SM4Interface::setTagLength()
     */
    public function setTagLength(int $tagLength)
    {
        $this->tagLength = $tagLength;
        return $this;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\SM4Interface::getTagLength()
     */
    public function getTagLength()
    {
        return $this->tagLength;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\SM4Interface::getCipherMethods()
     */
    public function getCipherMethods()
    {
        return $this->cipherMethods;
    }
}
