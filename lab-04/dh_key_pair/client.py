from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def generate_client_key_pair(parameters):
    # Tạo cặp khóa cho client dựa trên tham số nhận từ server
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_secret(private_key, server_public_key):
    # Tính toán bí mật chung (Shared Secret)
    shared_key = private_key.exchange(server_public_key)
    return shared_key

def main():
    # 1. Load server's public key từ file đã tạo ở bước trước
    with open("server_public_key.pem", "rb") as f:
        server_public_key = serialization.load_pem_public_key(f.read())

    # 2. Lấy tham số (parameters) từ public key của server
    parameters = server_public_key.parameters()
    
    # 3. Tạo cặp khóa của client
    private_key, public_key = generate_client_key_pair(parameters)

    # 4. Tính toán Shared Secret
    shared_secret = derive_shared_secret(private_key, server_public_key)

    # In kết quả dưới dạng Hex để kiểm tra
    print("Shared Secret:", shared_secret.hex())

if __name__ == "__main__":
    main()