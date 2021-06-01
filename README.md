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

同时我使用Python的ctypes库实现了Python对C函数的调用，您可以在`path.json`文件中配置对应操作系统下的C语言动态库路径

`present.py`中定义了一个类`present`，它的构造函数和加解密函数定义如下：

```py
def __init__(self, key)
```

您需要在构造时就以**长度为10的十进制list**形式来给定这个present类使用的密钥

```py
def encrypt(self, plain) -> list[int]

def decrypt(self, cipher) -> list[int]
```

加解密函数接收形式为**长度为8的十进制list**的明文或密文，返回**相同长度的list**

同样您需要在传入明文或密文前对它们进行分段和补齐

一个简单的使用Demo如下所示：

```py
key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
p = present(key)
text = [0, 0, 0, 0, 0, 0, 0, 0]
print(p.encrypt(text))
```

关于ctypes的使用细节，您可以参考[我攥写的博客](https://blog.mynameisdhr.com/PythonDeCtypesShiYong/)