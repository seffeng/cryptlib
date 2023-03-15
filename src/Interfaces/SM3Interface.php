<?php
/**
 * @link http://github.com/seffeng/
 * @copyright Copyright (c) 2023 seffeng
 */
namespace Seffeng\Cryptlib\Interfaces;

interface SM3Interface
{
    /**
     * 加密
     *
     * @author zxf
     * @date   2023-03-15
     * @param  string $plaintext
     * @return string
     */
    public function encrypt(string $plaintext);

    /**
     * 设置加密方法
     *
     * @author zxf
     * @date   2023-03-15
     * @param  string $algo
     * @return stasic
     */
    public function setAlgo(string $algo);

    /**
     * 获取加密方法
     *
     * @author zxf
     * @date   2023-03-15
     * @return string
     */
    public function getAlgo();
}