<?php
/**
 * @link http://github.com/seffeng/
 * @copyright Copyright (c) 2023 seffeng
 */
namespace Seffeng\Cryptlib\Interfaces;

interface SM4Interface
{
    /**
     * 加密
     *
     * @author zxf
     * @date   2023-03-10
     * @param string $plaintext
     * @return string
     */
    public function encrypt(string $plaintext);

    /**
     * 解密
     *
     * @author zxf
     * @date   2023-03-10
     * @param string $ciphertext
     * @return string
     */
    public function decrypt(string $ciphertext);

    /**
     *
     * @author zxf
     * @date   2023-03-10
     * @param integer|null $length
     * @param boolean $strong
     * @return string
     */
    public function createKey(&$strong = null);

    /**
     *
     * @author zxf
     * @date   2023-03-15
     * @param integer $length
     * @return static
     */
    public function setLength(int $length);

    /**
     *
     * @author zxf
     * @date   2023-03-15
     * @return integer
     */
    public function getLength();

    /**
     *
     * @author zxf
     * @date   2023-03-10
     * @param string $iv
     * @return static
     */
    public function setIv(string $iv);

    /**
     *
     * @author zxf
     * @date   2023-03-10
     * @return string
     */
    public function getIv();

    /**
     *
     * @author zxf
     * @date   2023-03-10
     * @param string $algo
     * @return static
     */
    public function setAlgo(string $algo);

    /**
     *
     * @author zxf
     * @date   2023-03-10
     * @return string
     */
    public function getAlgo();

    /**
     *
     * @author zxf
     * @date   2023-03-10
     * @param string $password
     * @return static
     */
    public function setPassword(string $password);

    /**
     *
     * @author zxf
     * @date   2023-03-10
     * @return string
     */
    public function getPassword();

    /**
     *
     * @author zxf
     * @date   2023-03-10
     * @param integer $options
     * @return static
     */
    public function setOptions(int $options);

    /**
     *
     * @author zxf
     * @date   2023-03-10
     * @return integer
     */
    public function getOptions();

    /**
     *
     * @author zxf
     * @date   2023-03-15
     * @param string $add
     * @return static
     */
    public function setAdd(string $add);

    /**
     *
     * @author zxf
     * @date   2023-03-15
     * @return string
     */
    public function getAdd();

    /**
     *
     * @author zxf
     * @date   2023-03-15
     * @param string $tag
     * @return static
     */
    public function setTag(string $tag);

    /**
     *
     * @author zxf
     * @date   2023-03-15
     * @return string
     */
    public function getTag();

    /**
     *
     * @author zxf
     * @date   2023-03-15
     * @param integer $tagLength
     * @return static
     */
    public function setTagLength(int $tagLength);

    /**
     *
     * @author zxf
     * @date   2023-03-15
     * @return integer
     */
    public function getTagLength();

    /**
     *
     * @author zxf
     * @date   2023-03-15
     * @return array
     */
    public function getCipherMethods();
}