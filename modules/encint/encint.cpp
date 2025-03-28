#include "encint.h"

CryptoCore::RandomGenerator* EncInt::_fae_static_rng = nullptr;

EncInt::EncInt(String p_type, int p_initial_value, bool p_validation_enabled) {
    type = p_type;
    encryption_key = generate_encryption_key();
    validation_enabled = p_validation_enabled;
    set_value(p_initial_value);
}

EncInt::~EncInt() {
    // 析构函数，可根据需要添加清理操作
}

int EncInt::encrypt(int value) {
    return value ^ encryption_key;
}

int EncInt::decrypt(int encrypted_value) const {
    return encrypted_value ^ encryption_key;
}

int EncInt::add_checksum(int value) {
    int checksum = 0;
    char* data = reinterpret_cast<char*>(&value);
    for (size_t i = 0; i < sizeof(int); ++i) {
        checksum += static_cast<unsigned char>(data[i]);
    }
    return checksum;
}

int EncInt::generate_encryption_key() {
    PackedByteArray iv;
    iv.resize(16);
    if (!_fae_static_rng) {
        _fae_static_rng = memnew(CryptoCore::RandomGenerator);
        if (_fae_static_rng->init() != OK) {
            memdelete(_fae_static_rng);
            _fae_static_rng = nullptr;
            ERR_FAIL_V_MSG(0, "Failed to initialize random number generator.");
        }
    }
    Error err = _fae_static_rng->get_random_bytes(iv.ptrw(), 16);
    ERR_FAIL_COND_V(err != OK, 0);

    int key = 0;
    memcpy(&key, iv.ptr(), sizeof(int));
    return key;
}

int EncInt::get_value() const {
    int decrypted = decrypt(encrypted_value);
    if (validation_enabled) {
        int current_checksum = add_checksum(decrypted);
        if (current_checksum != add_checksum_value) {
            emit_signal("validation_failed", decrypted, type);
        }
    }
    return decrypted;
}

void EncInt::set_value(int p_value) {
    encrypted_value = encrypt(p_value);
    if (validation_enabled) {
        add_checksum_value = add_checksum(p_value);
    }
    emit_signal("value_changed", p_value);
}

int EncInt::operator+(const EncInt& other) const {
    int this_value = get_value();
    int other_value = other.get_value();
    return this_value + other_value;
}

int EncInt::operator+(int other) const {
    int this_value = get_value();
    return this_value + other;
}

float EncInt::operator+(float other) const {
    int this_value = get_value();
    return static_cast<float>(this_value) + other;
}

int EncInt::operator-(const EncInt& other) const {
    int this_value = get_value();
    int other_value = other.get_value();
    return this_value - other_value;
}

int EncInt::operator-(int other) const {
    int this_value = get_value();
    return this_value - other;
}

float EncInt::operator-(float other) const {
    int this_value = get_value();
    return static_cast<float>(this_value) - other;
}

int EncInt::operator*(const EncInt& other) const {
    int this_value = get_value();
    int other_value = other.get_value();
    return this_value * other_value;
}

int EncInt::operator*(int other) const {
    int this_value = get_value();
    return this_value * other;
}

float EncInt::operator*(float other) const {
    int this_value = get_value();
    return static_cast<float>(this_value) * other;
}

int EncInt::operator/(const EncInt& other) const {
    int this_value = get_value();
    int other_value = other.get_value();
    if (other_value == 0) {
        // 处理除零错误
        return this_value;
    }
    return this_value / other_value;
}

int EncInt::operator/(int other) const {
    int this_value = get_value();
    if (other == 0) {
        // 处理除零错误
        return this_value;
    }
    return this_value / other;
}

float EncInt::operator/(float other) const {
    int this_value = get_value();
    if (other == 0.0f) {
        // 处理除零错误
        return static_cast<float>(this_value);
    }
    return static_cast<float>(this_value) / other;
}

EncInt& EncInt::operator+=(const EncInt& other) {
    int this_value = get_value();
    int other_value = other.get_value();
    set_value(this_value + other_value);
    return *this;
}

EncInt& EncInt::operator+=(int other) {
    int this_value = get_value();
    set_value(this_value + other);
    return *this;
}

EncInt& EncInt::operator+=(float other) {
    int this_value = get_value();
    int result = static_cast<int>(this_value + other);
    set_value(result);
    return *this;
}

EncInt& EncInt::operator-=(const EncInt& other) {
    int this_value = get_value();
    int other_value = other.get_value();
    set_value(this_value - other_value);
    return *this;
}

EncInt& EncInt::operator-=(int other) {
    int this_value = get_value();
    set_value(this_value - other);
    return *this;
}

EncInt& EncInt::operator-=(float other) {
    int this_value = get_value();
    int result = static_cast<int>(this_value - other);
    set_value(result);
    return *this;
}

int EncInt::operator%(int other) const {
    int this_value = get_value();
    if (other == 0) {
        // 处理除零错误
        return this_value;
    }
    return this_value % other;
}

EncInt::operator int() const {
    return get_value();
}

EncInt& EncInt::operator=(int p_value) {
    set_value(p_value);
    return *this;
}

EncInt& EncInt::operator=(float p_value) {
    set_value(static_cast<int>(p_value));
    return *this;
}

void EncInt::_notification(int p_what) {
    switch (p_what) {
        case NOTIFICATION_POSTINITIALIZE:
            // 初始化后可添加额外操作
            break;
    }
}