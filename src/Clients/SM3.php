<?php
/**
 * @link http://github.com/seffeng/
 * @copyright Copyright (c) 2023 seffeng
 */
namespace Seffeng\Cryptlib\Clients;

use Seffeng\Cryptlib\Interfaces\SM3Interface;

class SM3 implements SM3Interface
{
    /**
     * @var string
     */
    protected $algo = 'sm3';

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\SM3Interface::encrypt()
     */
    public function encrypt(string $plaintext)
    {
        return openssl_digest($plaintext, $this->getAlgo());
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\SM3Interface::setAlgo()
     */
    public function setAlgo(string $algo)
    {
        $this->algo = $algo;
        return $this;
    }

    /**
     *
     * {@inheritDoc}
     * @see \Seffeng\Cryptlib\Interfaces\SM3Interface::getAlgo()
     */
    public function getAlgo()
    {
        return $this->algo;
    }
}
