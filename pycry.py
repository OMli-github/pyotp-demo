import base64

def encrypt(text):
    key = 198  # 固定密钥，可根据需要修改
    encrypted_bytes = bytes([ord(c) ^ key for c in text])
    return base64.b64encode(encrypted_bytes).decode('utf-8')

def decrypt(encrypted_text):
    key = 198  # 必须与加密密钥相同
    encrypted_bytes = base64.b64decode(encrypted_text)
    return ''.join([chr(b ^ key) for b in encrypted_bytes])


if __name__ == "__main__":
    # 示例用法
    original = "JBSWY3DPEHPK3PXP"
    print("原文:", original)

    encrypted = encrypt(original)
    print("加密后:", encrypted)

    decrypted = decrypt(encrypted)
    print("解密后:", decrypted)