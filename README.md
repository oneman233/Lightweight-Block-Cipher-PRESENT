# Lightweight-Block-Cipher-PRESENT

`80-bit PRESENT.c`主要有以下两个函数：

```c
void present_encrypt(const uint8_t *plain, const uint8_t *key, uint8_t *ans)
```

用于present的加密，接收64bit的明文指针`plain`、80bit的密钥指针`key`以及64bit的结果指针`ans`，加密结果保存在`ans`指针中

```c
void present_decrypt(const uint8_t *cipher, const uint8_t *key, uint8_t *ans)
```

用于present的解密，接收64bit的明文指针`cipher`、80bit的密钥指针`key`以及64bit的结果指针`ans`，加密结果保存在`ans`指针中

`main()`函数则用于简单测试加密解密的正确性

**注意加密解密前需要手动对需要处理的文本分段或补齐长度**

加密函数使用了动态计算轮密钥的方法，解密函数则提前计算好了轮密钥，所以加密解密的性能可能会有一定差别