#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include <cstring> // Cho memcmp
#include <iomanip> // Cho in hex

#include "CryptoManager.h" // File header đã tối ưu ở bước trước

using namespace std;

// --- Helper: In mảng byte ra màn hình (để debug) ---
void printHex(const string& label, const vector<uint8_t>& data) {
    cout << label << ": ";
    for (auto b : data) {
        cout << hex << setfill('0') << setw(2) << (int)b;
    }
    cout << dec << endl;
}

// --- Helper: So sánh 2 vector ---
bool areVectorsEqual(const vector<uint8_t>& v1, const vector<uint8_t>& v2) {
    if (v1.size() != v2.size()) return false;
    return memcmp(v1.data(), v2.data(), v1.size()) == 0;
}

// ================= TEST CASES =================

// void test_RandomBytes() {
//     cout << "\n[TEST] Random Bytes Generation..." << endl;
//     auto bytes1 = CryptoManager::generateRandomBytes(16);
//     auto bytes2 = CryptoManager::generateRandomBytes(16);

//     assert(bytes1.size() == 16);
//     assert(bytes2.size() == 16);
//     // Xác suất 2 chuỗi ngẫu nhiên 16 byte trùng nhau là cực thấp
//     assert(!areVectorsEqual(bytes1, bytes2)); 
//     cout << "PASSED" << endl;
// }

void test_PBKDF2_PasswordHashing() {
    cout << "\n[TEST] Password Hashing (PBKDF2)..." << endl;
    string password = "MySuperSecretPassword123!";
    
    vector<uint8_t> salt, hash;
    
    // 1. Tạo Hash
    CryptoManager::hashPasswordPBKDF2(password, salt, hash);
    
    assert(salt.size() == 16); // Salt size defined in cpp
    assert(hash.size() == 32); // SHA256 size

    // 2. Xác minh đúng mật khẩu
    bool valid = CryptoManager::verifyPasswordPBKDF2(password, salt, hash);
    assert(valid == true);

    // 3. Xác minh sai mật khẩu
    bool invalid = CryptoManager::verifyPasswordPBKDF2("WrongPassword", salt, hash);
    assert(invalid == false);

    cout << "PASSED" << endl;
}

void test_DiffieHellman_KeyExchange() {
    cout << "\n[TEST] Diffie-Hellman Key Exchange..." << endl;

    // Giả lập Alice
    vector<uint8_t> pubA, privA;
    CryptoManager::generateDHKeyPair(pubA, privA);

    // Giả lập Bob
    vector<uint8_t> pubB, privB;
    CryptoManager::generateDHKeyPair(pubB, privB);

    // Alice tính Shared Secret (Dùng PrivA + PubB)
    vector<uint8_t> secretA;
    CryptoManager::deriveSharedSecret(privA, pubB, secretA);

    // Bob tính Shared Secret (Dùng PrivB + PubA)
    vector<uint8_t> secretB;
    CryptoManager::deriveSharedSecret(privB, pubA, secretB);

    // Kiểm tra độ dài (HKDF output 32 bytes)
    assert(secretA.size() == 32);
    assert(secretB.size() == 32);

    // Hai bên phải có chung một bí mật
    if (areVectorsEqual(secretA, secretB)) {
        printHex("Shared Secret", secretA);
        cout << "PASSED: Alice and Bob have the same secret." << endl;
    } else {
        cerr << "FAILED: Secrets do not match!" << endl;
        exit(1);
    }
}

void test_AES_GCM() {
    cout << "\n[TEST] AES-GCM Encryption/Decryption..." << endl;

    // Tạo key ngẫu nhiên 32 byte (256 bit)
    vector<uint8_t> key = CryptoManager::generateRandomBytes(32);
    
    // Dữ liệu gốc
    string message = "This is a secret note content.";
    vector<uint8_t> plaintext(message.begin(), message.end());

    vector<uint8_t> iv, tag, ciphertext;

    // 1. Mã hóa
    bool encSuccess = CryptoManager::aesEncrypt(plaintext, key, iv, tag, ciphertext);
    assert(encSuccess);
    assert(iv.size() == 12);
    assert(tag.size() == 16);
    assert(ciphertext.size() == plaintext.size());

    // 2. Giải mã đúng
    vector<uint8_t> decrypted;
    bool decSuccess = CryptoManager::aesDecrypt(ciphertext, key, iv, tag, decrypted);
    assert(decSuccess);
    
    string decStr(decrypted.begin(), decrypted.end());
    assert(decStr == message);

    // 3. Giải mã thất bại (giả mạo ciphertext)
    vector<uint8_t> tamperedCipher = ciphertext;
    tamperedCipher[0] ^= 0xFF; // Đổi 1 bit byte đầu tiên
    vector<uint8_t> badOutput;
    bool tamperSuccess = CryptoManager::aesDecrypt(tamperedCipher, key, iv, tag, badOutput);
    
    assert(tamperSuccess == false); // GCM phải phát hiện giả mạo và trả về false

    cout << "PASSED" << endl;
}

void test_KeyWrapping_Scenario() {
    cout << "\n[TEST] Full Scenario: Sending Encrypted Key..." << endl;

    // BƯỚC 1: Thiết lập kênh an toàn (DH)
    // Alice & Bob đã có Shared Secret từ bước DH trước đó
    // Giả sử Shared Secret là random byte để test nhanh
    vector<uint8_t> sharedSecret = CryptoManager::generateRandomBytes(32);

    // BƯỚC 2: Alice tạo Note Key (AES)
    vector<uint8_t> originalNoteKey = CryptoManager::generateRandomBytes(32);
    
    // BƯỚC 3: Alice mã hóa Note Key bằng Shared Secret để gửi cho Bob
    vector<uint8_t> encryptedKeyPackage;
    bool wrapSuccess = CryptoManager::encryptAESKeyForRecipient(
        originalNoteKey, sharedSecret, encryptedKeyPackage
    );
    assert(wrapSuccess);

    // BƯỚC 4: Bob nhận package và giải mã để lấy Note Key
    vector<uint8_t> unwrappedNoteKey;
    bool unwrapSuccess = CryptoManager::decryptAESKeyFromSender(
        encryptedKeyPackage, sharedSecret, unwrappedNoteKey
    );
    assert(unwrapSuccess);

    // BƯỚC 5: Kiểm tra Key Bob nhận được có giống Key Alice tạo không
    assert(areVectorsEqual(originalNoteKey, unwrappedNoteKey));

    cout << "PASSED: Key wrapping works correctly." << endl;
}

void test_Base64() {
    cout << "\n[TEST] Base64 Encode/Decode..." << endl;
    string original = "Hello World";
    vector<uint8_t> data(original.begin(), original.end());

    string encoded = CryptoManager::base64Encode(data);
    // "Hello World" in Base64 is "SGVsbG8gV29ybGQ="
    // Lưu ý: OpenSSL có thể thêm newline, cần cẩn trọng khi so sánh string cứng
    
    vector<uint8_t> decoded = CryptoManager::base64Decode(encoded);
    string result(decoded.begin(), decoded.end());

    assert(result == original);
    cout << "PASSED" << endl;
}

int main() {
    try {
        // test_RandomBytes();
        test_PBKDF2_PasswordHashing();
        test_DiffieHellman_KeyExchange();
        test_AES_GCM();
        test_KeyWrapping_Scenario();
        test_Base64();

        cout << "\n========================================" << endl;
        cout << "ALL TESTS PASSED SUCCESSFULLY!" << endl;
        cout << "========================================" << endl;
    } catch (const std::exception& e) {
        cerr << "\n[EXCEPTION] Test failed with error: " << e.what() << endl;
        return 1;
    }
    return 0;
}