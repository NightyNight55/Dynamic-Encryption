from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537, 
        # public_exponent 是用於生成 RSA 密鑰時的一個參數，
        #具體來說，它定義了 RSA 加密中公開密鑰的「公開指數」。
        #這個指數在加密過程中與模數一起工作，用來加密訊息。
        #它的選擇對於加密的安全性和效率有一定的影響。
        key_size=2048,
    )
    
    public_key = private_key.public_key()
    
    # 將密鑰序列化
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem, public_pem