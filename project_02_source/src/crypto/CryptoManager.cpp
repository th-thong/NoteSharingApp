#include "CryptoManager.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/dh.h>
#include <openssl/kdf.h>
#include <openssl/err.h>

#include <vector>
#include <string>
#include <stdexcept>
#include <iostream>

using namespace std;

//--------------------------------------------------------------------
//                          Các hàm bổ trợ
//--------------------------------------------------------------------


// Hàm để kiểm tra và xử lý lỗi OpenSSL
// ERR_get_error là mã lỗi (số), không đọc được
// ERR_error_string_n là string có thể đọc được
// throw ra mô tả lỗi
void throwOnError(const std::string& msg) {
    unsigned long err = ERR_get_error();
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    throw std::runtime_error(msg + ": " + buf);
}


// Tạo vector các byte ngẫu nhiên có độ dài xác định
// Hàm RAND_bytes để tạo ra salt cho PBKDF2 và IV (initialization vector) cho AES-GCM
vector<uint8_t> CryptoManager::generateRandomBytes(size_t size) {
    vector<uint8_t> buf(size);
    if (RAND_bytes(buf.data(), size) != 1)
        throwOnError("RAND_bytes failed");
    return buf;
}


//--------------------------------------------------------------------
//                  Bảo mật mật khẩu người dùng
//--------------------------------------------------------------------
// Các thuật toán sử dụng: PBKDF2, hàm băm SHA256


// Băm mật khẩu của người dùng mới đăng ký
// PKCS5_PBKDF2_HMAC là hàm của OpenSSL
void CryptoManager::hashPasswordPBKDF2 (
    const string& password,
    vector<uint8_t>& saltOut,
    vector<uint8_t>& hashOut) 
{
    const int SALT_SIZE = 16;     
    const int HASH_SIZE = 32;       
    const int ITER = 150000; // Số lần lặp (lặp càng nhiều, càng khó brute-force)

    saltOut = generateRandomBytes(SALT_SIZE);   
    hashOut.resize(HASH_SIZE);              

    if (PKCS5_PBKDF2_HMAC(
            password.c_str(), password.size(),
            saltOut.data(), saltOut.size(),
            ITER,
            EVP_sha256(), // hàm băm là EVP_sha256, lưu vào hashOut
            HASH_SIZE,
            hashOut.data()) != 1) {
        throwOnError("PBKDF2 hash failed");
    }
}


// Xác minh mật khẩu, sử dụng password do người dùng nhập vào
// Giống hàm hashPasswordPBKDF2, khác ở chỗ khúc cuối có dòng đối sánh
// so hash mới tính với hash đã lưu, nếu khớp (diff = 0), trả về 1
bool CryptoManager::verifyPasswordPBKDF2(
    const string& password,
    const vector<uint8_t>& storedSalt,  // salt đã lưu
    const vector<uint8_t>& storedHash)  // hash đã lưu
{
    vector<uint8_t> calcHash(storedHash.size());

    if (PKCS5_PBKDF2_HMAC(
            password.c_str(), password.size(),
            storedSalt.data(), storedSalt.size(),
            150000,
            EVP_sha256(),
            storedHash.size(),
            calcHash.data()) != 1) {
        return false;
    }

    if (calcHash.size() != storedHash.size()) return false;
    unsigned diff = 0;
    for (size_t i = 0; i < calcHash.size(); i++)
        diff |= calcHash[i] ^ storedHash[i];
    return diff == 0;
}



//-------------------------------------------------------------------
//                  Trao đổi khoá Diffie-Hellman
//-------------------------------------------------------------------

// Tạo cặp khoá công khai và khoá bí mật
void CryptoManager::generateDHKeyPair(
    vector<uint8_t>& publicKeyOut,
    vector<uint8_t>& privateKeyOut)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!pctx) throwOnError("EVP_PKEY_CTX_new_id failed");

    EVP_PKEY *pkey = nullptr;
    if (EVP_PKEY_keygen_init(pctx) != 1) {
        EVP_PKEY_CTX_free(pctx);
        throwOnError("keygen_init failed");
    }

    if (EVP_PKEY_keygen(pctx, &pkey) != 1) {
        EVP_PKEY_CTX_free(pctx);
        throwOnError("keygen failed");
    }

    EVP_PKEY_CTX_free(pctx);

    size_t publen = 0, privlen = 0;
    if (EVP_PKEY_get_raw_public_key(pkey, NULL, &publen) != 1 ||
        EVP_PKEY_get_raw_private_key(pkey, NULL, &privlen) != 1) {
        EVP_PKEY_free(pkey);
        throwOnError("get_raw_key_len failed");
    }

    publicKeyOut.resize(publen);
    privateKeyOut.resize(privlen);

    if (EVP_PKEY_get_raw_public_key(pkey, publicKeyOut.data(), &publen) != 1 ||
        EVP_PKEY_get_raw_private_key(pkey, privateKeyOut.data(), &privlen) != 1) {
        EVP_PKEY_free(pkey);
        throwOnError("get_raw_key failed");
    }

    EVP_PKEY_free(pkey);
}


// Tính toán khoá bí mật chung (A dùng khóa bí mật của A và khóa công khai của B)
void CryptoManager::deriveSharedSecret(
    const vector<uint8_t>& myPrivateKey,    // Khoá bí mật của người dùng hiện tại
    const vector<uint8_t>& peerPublicKey,   // Khoá bí mật của người còn lại
    vector<uint8_t>& sharedSecretOut)       // Khóa cuối cùng dùng để mã hóa/giải mã khóa AES của ghi chú.
{
    // Tạo EVP_PKEY từ raw private
    EVP_PKEY* priv = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, 
        nullptr,
        myPrivateKey.data(), 
        myPrivateKey.size());
    if (!priv) throwOnError("Load private key failed");

    // Tạo EVP_PKEY từ raw public
    EVP_PKEY* pub = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519, 
        nullptr,
        peerPublicKey.data(),
        peerPublicKey.size());
    if (!pub) {
        EVP_PKEY_free(priv);
        throwOnError("Load public key failed");
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, nullptr);
    if (!ctx) {
        EVP_PKEY_free(priv); EVP_PKEY_free(pub);
        throwOnError("PKEY_CTX_new failed");
    }

    if (EVP_PKEY_derive_init(ctx) != 1) {
        EVP_PKEY_free(priv); EVP_PKEY_free(pub); EVP_PKEY_CTX_free(ctx);
        throwOnError("derive_init failed");
    }

    if (EVP_PKEY_derive_set_peer(ctx, pub) != 1) {
        EVP_PKEY_free(priv); EVP_PKEY_free(pub); EVP_PKEY_CTX_free(ctx);
        throwOnError("derive_set_peer failed");
    }

    size_t secretLen = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &secretLen) != 1) {
        EVP_PKEY_free(priv); EVP_PKEY_free(pub); EVP_PKEY_CTX_free(ctx);
        throwOnError("derive length failed");
    }

    sharedSecretOut.resize(secretLen);
    if (EVP_PKEY_derive(ctx, sharedSecretOut.data(), &secretLen) != 1) {
        EVP_PKEY_free(priv); EVP_PKEY_free(pub); EVP_PKEY_CTX_free(ctx);
        throwOnError("derive failed");
    }

    //Expected: secretlen có độ dài 32 bit
    sharedSecretOut.resize(secretLen);

    EVP_PKEY_free(priv);
    EVP_PKEY_free(pub);
    EVP_PKEY_CTX_free(ctx);
}



// ----------------------------------------------------------------
//                      Mã hoá/Giải mã AES-GCM
// ----------------------------------------------------------------
// Thuật toán mã hoá AES-256 trong chế độ Galois/Counter Mode (GCM)


// Mã hoá plaintext bằng aeskey
bool CryptoManager::aesEncrypt(
    const vector<uint8_t>& plaintext,   // Nội dung cần được mã hoá
    const vector<uint8_t>& aesKey,      // Khoá đối xứng dùng để mã hoá
    vector<uint8_t>& ivOut,             // IV (được gửi cùng ciphertext), đảm bảo mỗi lần mã hoá là duy nhất
    vector<uint8_t>& tagOut,            // Người nhận dùng tagOut để xác thực tính toàn vẹn và nguồn gốc gửi ghi chú
    vector<uint8_t>& ciphertextOut)     // ciphertext (output)
{
    const int IV_LEN = 12;
    const int TAG_LEN = 16;

    ivOut = generateRandomBytes(IV_LEN);
    tagOut.resize(TAG_LEN);
    ciphertextOut.resize(plaintext.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        return false;

    EVP_EncryptInit_ex(ctx, nullptr, nullptr, aesKey.data(), ivOut.data());

    int len = 0, ciphertext_len = 0;
    if (EVP_EncryptUpdate(ctx, ciphertextOut.data(), &len,
                          plaintext.data(), plaintext.size()) != 1)
        return false;
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertextOut.data() + len, &len) != 1)
        return false;
    ciphertext_len += len;

    ciphertextOut.resize(ciphertext_len);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tagOut.data());
    EVP_CIPHER_CTX_free(ctx);
    return true;
}


// Giải mã ciphertext + xác thực tính toàn vẹn
// Các biến giống hệt như trong hàm aesEncrypt
bool CryptoManager::aesDecrypt(
    const vector<uint8_t>& ciphertext,
    const vector<uint8_t>& aesKey,      
    const vector<uint8_t>& iv,
    const vector<uint8_t>& tag,
    vector<uint8_t>& plaintextOut)
{
    plaintextOut.resize(ciphertext.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        return false;

    EVP_DecryptInit_ex(ctx, nullptr, nullptr, aesKey.data(), iv.data());

    int len = 0, plaintext_len = 0;
    if (EVP_DecryptUpdate(ctx, plaintextOut.data(), &len,
                          ciphertext.data(), ciphertext.size()) != 1)
        return false;
    plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), (void*)tag.data());

    if (EVP_DecryptFinal_ex(ctx, plaintextOut.data() + len, &len) != 1)
        return false;

    plaintext_len += len;
    plaintextOut.resize(plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}



//------------------------------------------------------------------
//                          Mã hoá khoá AES
//------------------------------------------------------------------


// Người gửi A mã hóa khóa AES của ghi chú để gửi cho người nhận B
bool CryptoManager::encryptAESKeyForRecipient(
    const vector<uint8_t>& aesKey,          // Khoá AES để mã hoá nội dung ghi chú
    const vector<uint8_t>& sharedSecret,    // Khoá bí mật chung DH
    vector<uint8_t>& encryptedKeyOut)       // Chuỗi byte kết hợp IV, Tag và Khóa AES đã mã hóa
{
    vector<uint8_t> iv, tag, ct; //IV, Tag và Ciphertext được tạo ra từ hàm aesEncrypt
    if (!aesEncrypt(aesKey, sharedSecret, iv, tag, ct))
        return false;

    encryptedKeyOut.clear();
    encryptedKeyOut.insert(encryptedKeyOut.end(), iv.begin(), iv.end());
    encryptedKeyOut.insert(encryptedKeyOut.end(), tag.begin(), tag.end());
    encryptedKeyOut.insert(encryptedKeyOut.end(), ct.begin(), ct.end());
    return true;
}


// Người nhận B giải mã khóa AES của ghi chú.
bool CryptoManager::decryptAESKeyFromSender(
    const vector<uint8_t>& encryptedKey,    // Chuỗi byte kết hợp IV, Tag và Khóa AES đã mã hóa nhận được từ A.
    const vector<uint8_t>& sharedSecret,    // Khóa bí mật chung DH
    vector<uint8_t>& aesKeyOut)             // Khoá AES
{
    const int IV_LEN = 12;
    const int TAG_LEN = 16;

    if (encryptedKey.size() < IV_LEN + TAG_LEN)
        return false;

    std::vector<uint8_t> iv(
        encryptedKey.begin(),
        encryptedKey.begin() + IV_LEN);

    std::vector<uint8_t> tag(
        encryptedKey.begin() + IV_LEN,
        encryptedKey.begin() + IV_LEN + TAG_LEN);

    std::vector<uint8_t> ct(
        encryptedKey.begin() + IV_LEN + TAG_LEN,
        encryptedKey.end());

    return aesDecrypt(ct, sharedSecret, iv, tag, aesKeyOut);
}



//-------------------------------------------------------------------
//                      Mã hoá/Giải mã Base64
//-------------------------------------------------------------------


// Mã hóa dữ liệu byte thành chuỗi Base64
// Hàm EVP_EncodeBlock chuyển đổi dữ liệu nhị phân 
// (như khóa mã hóa, ciphertext) thành định dạng văn bản an toàn 
// để truyền qua các giao thức dựa trên văn bản
string CryptoManager::base64Encode(const vector<uint8_t>& data) {
    int encodedLen = 4 * ((data.size() + 2) / 3);
    std::string out(encodedLen, '\0');

    int outLen = EVP_EncodeBlock(
        reinterpret_cast<unsigned char*>(&out[0]),
        data.data(),
        data.size()
    );

    out.resize(outLen);
    return out;
}


// Giải mã chuỗi Base64 trở lại dữ liệu byte.
// Dùng hàm EVP_DecodeBlock, ngược lại với EVP_EncodeBlock ở trên
vector<uint8_t> CryptoManager::base64Decode(const string& encoded) {
    int len = encoded.size();
    std::vector<uint8_t> out(len); // buffer lớn hơn cần thiết

    int decodedLen = EVP_DecodeBlock(
        out.data(),
        reinterpret_cast<const unsigned char*>(encoded.data()),
        len);

    if (decodedLen < 0) return {}; // invalid base64

    // Xử lý padding: '=' có thể là 1 hoặc 2 ký tự
    int padding = 0;
    if (encoded.size() >= 1 && encoded[encoded.size() - 1] == '=') padding++;
    if (encoded.size() >= 2 && encoded[encoded.size() - 2] == '=') padding++;

    out.resize(decodedLen - padding);
    return out;
}

