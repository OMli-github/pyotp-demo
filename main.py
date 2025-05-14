import streamlit as st
import base64
import os
import json
import logging
from logging.handlers import RotatingFileHandler
import traceback

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

import pyotp
# 配置日志
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s",
                    handlers=[logging.FileHandler("app.log"), logging.StreamHandler()])

# 安全配置
SESSION_STATE = st.session_state
MAX_CIPHERS = 5
KEY_STORAGE_PATH = "key_storage.json"

def save_key_to_disk(key):
    with open(KEY_STORAGE_PATH, 'w') as f:
        json.dump({"key": key}, f)

def load_key_from_disk():
    if os.path.exists(KEY_STORAGE_PATH):
        with open(KEY_STORAGE_PATH, 'r') as f:
            data = json.load(f)
            return data.get("key")
    return None

def decrypts(encrypted_text):
    key = 198  # 必须与加密密钥相同
    encrypted_bytes = base64.b64decode(encrypted_text)
    return ''.join([chr(b ^ key) for b in encrypted_bytes])
def decrypt(combined: str, secret_key: str, user_otp: str, iterations: int = 100000) -> str:
    """使用 AES-GCM 解密数据，需提供TOTP验证码"""
    # 解析数据（时间戳:salt:nonce:ciphertext:tag）
    parts = combined.split(':')
    if len(parts) != 5:
        raise ValueError("无效的密文格式")
    timestamp_str, salt_b64, nonce_b64, ciphertext_b64, tag_b64 = parts
    timestamp = int(timestamp_str)
    salt = base64.b64decode(salt_b64)
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    tag = base64.b64decode(tag_b64)
    try:
        key= decrypts(secret_key)
    except Exception as e:
        raise ValueError("无法解密密钥，请检查密钥")
    # 验证用户输入的TOTP码
    totp = pyotp.TOTP(key)
    if not totp.verify(user_otp, valid_window=1):  # 允许±30秒时间误差
        raise ValueError("TOTP验证失败，请检查6位数验证码,或者密钥是否正确")

    # 重新生成PBKDF2密钥
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    otp = totp.at(timestamp)  # 使用加密时的TOTP码
    key = kdf.derive(f"{key}{otp}".encode())

    # AES-GCM 解密
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()
    except InvalidTag:
        raise ValueError("解密失败：认证标签无效（数据可能被篡改）")


# 页面模块
def install_key_page():
    """密钥安装模块"""
    st.header("🔑 密钥管理")
    (col1,) = st.columns(1)
    with col1:
        new_key = st.text_input("输入密钥", type="password",)
    if st.button("提交密钥"):
        if not new_key:
            st.error("必须提供密钥")
            return
        if len(new_key) < 24:
            st.error("密钥长度不足")
            return
        try:
            save_key_to_disk(new_key)
            st.success("✅ 密钥更新成功！  ⚠️ 请妥善保存TOTP信息并立即配置到验证器应用中！")
            logging.info("New key installed")
        except Exception as e:
            st.error(f"❌ 无效的密钥格式: {str(e)}")
            logging.error(f"Key install error: {str(e)}")

def decrypt_page():
    """密文解密模块"""
    st.header("🔓 密文解密")

    key_data = load_key_from_disk()

    if key_data is None:
        st.warning("⚠️ 请先安装加密密钥")
        return

    # TOTP验证
    totp_input = st.text_input("输入TOTP验证码")

    # 密文输入
    ciphers = st.text_area(
        f"输入待解密的密文（最多{MAX_CIPHERS}条，换行分隔）",
        height=200,
        help="每条密文应为Fernet加密的Base64字符串"
    ).split('\n')[:MAX_CIPHERS]

    if st.button("🚀 开始解密"):
        results = []
        for idx, cipher in enumerate(ciphers):
            cipher = cipher.strip()
            if not cipher:
                continue
            if idx > 5:
                st.error("最多只能输入5条密文")
                break
            try:
                decrypted = decrypt(cipher, key_data, totp_input)
                results.append(f"[{idx + 1}] ✅ 成功: {decrypted}")
                logging.info(f"Decrypted cipher {idx + 1}")
            except InvalidToken:
                results.append(f"[{idx + 1}] ❌ 错误: 无效的密文格式")
                logging.warning(f"Invalid cipher at position {idx + 1}")
            except Exception as e:
                results.append(f"[{idx + 1}] ⚠️ 错误: {str(e)}")
                logging.error(f"Decryption error: {str(e)}")

        st.text_area("解密结果", '\n'.join(results), height=200)

# 主界面
def main():
    # 安全头设置
    st.set_page_config(
        page_title="安全解密服务",
        page_icon="🛡️",
        layout="centered"
    )

    # 自定义样式
    st.markdown("""
    <style>
    .stTextArea textarea {font-family: monospace !important;}
    .stAlert {border-left: 4px solid #2ecc71;}
    </style>
    """, unsafe_allow_html=True)

    # 侧边栏导航
    with st.sidebar:
        st.title("🛡️ 导航")
        page = st.radio("选择功能模块", ["密文解密", "密钥管理"])
        st.markdown("---")

    if page == "密文解密":
        decrypt_page()
    else:
        install_key_page()

if __name__ == "__main__":
    main()