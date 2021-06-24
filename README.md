# Lightweight-Block-Cipher-PRESENT

`80-bit PRESENT.h` consists of the following two functions：

```c
void present_encrypt(const uint8_t *plain, const uint8_t *key, uint8_t *ans);

void present_decrypt(const uint8_t *cipher, const uint8_t *key, uint8_t *ans);
```

Parameter Description:

* `plain`: 64-bit pointer
* `cipher`: 64-bit pointer
* `key`: 80-bit pointer
* `ans`: 64-bit pointer

Both functions have no return value, results of encryption and decryption will be stored in the `ans` pointer.

This cipher will work for **31** rounds, and `test.c` is used for testing the correctness of both functions.

**ATTENTION: You should split your data into 64-bit segments before use both functions.**

The encryption function updates round keys dynamically, while the decryption function calculates all round keys in advance, so their performances might be a little different.
