import base64

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def encrypt(key, content):
    padded_data = pad(content.encode("utf-8"), AES.block_size)
    cipher = AES.new(base64.b64decode(key), AES.MODE_CBC)
    ciphertext = cipher.encrypt(padded_data)
    # 拼接向量IV和加密文本，base64编码
    encrypted_data = base64.b64encode(cipher.iv + ciphertext)
    return encrypted_data.decode()

def decrypt(key, encrypted_content):
    encrypted_data = base64.b64decode(encrypted_content)
    # 获取向量IV和加密文本，解密
    iv = encrypted_data[:AES.block_size]
    ciphertext = encrypted_data[AES.block_size:]
    cipher = AES.new(base64.b64decode(key), AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_data

def generate_random_aes_key():
    key = get_random_bytes(32)
    key_base64 = base64.b64encode(key).decode('utf-8')
    return key_base64

def main():
    # 生成随机秘钥
    key_base64 = generate_random_aes_key()
    print(f"Random AES-256 Key in Base64: {key_base64}")
    # aes加密
    content = "test123456"
    encrypted_content = encrypt(key_base64, content)
    print(f"Encrypted content: {encrypted_content}")
    # aes解密
    decrypt_content = decrypt(key_base64, encrypted_content)
    print(f"Decrypt content: {decrypt_content.decode()}")

if __name__ == '__main__':
    main()















