#ifndef ENC_INT_H
#define ENC_INT_H

#include "core/object/object.h"
#include "core/string/ustring.h"
#include "core/crypto/crypto_core.h"


class EncInt : public Object {
    GDCLASS(EncInt, Object);

    int encrypted_value;
    int encryption_key;
    bool validation_enabled;
    int add_checksum_value;
    String type;

    static CryptoCore::RandomGenerator* _fae_static_rng;

    static void _bind_methods();

    // 加密方法
    int encrypt(int value);
    // 解密方法
    int decrypt(int encrypted_value) const;
    // 计算加法校验和
    int add_checksum(int value);
    // 生成加密密钥
    int generate_encryption_key();

protected:
    void _notification(int p_what);

public:
    EncInt(String p_type, int p_initial_value = 0, bool p_validation_enabled = false);
    ~EncInt();

    // 获取值（解密后）
    int get_value() const;
    // 设置值（加密后存储）
    void set_value(int p_value);

    // 元方法重载
    int operator+(const EncInt& other) const;
    int operator+(int other) const;
    float operator+(float other) const;

    int operator-(const EncInt& other) const;
    int operator-(int other) const;
    float operator-(float other) const;

    int operator*(const EncInt& other) const;
    int operator*(int other) const;
    float operator*(float other) const;

    int operator/(const EncInt& other) const;
    int operator/(int other) const;
    float operator/(float other) const;

    EncInt& operator+=(const EncInt& other);
    EncInt& operator+=(int other);
    EncInt& operator+=(float other);

    EncInt& operator-=(const EncInt& other);
    EncInt& operator-=(int other);
    EncInt& operator-=(float other);

    int operator%(int other) const;

    // 类型转换操作符，用于隐式转换为 int
    operator int() const;
    // 赋值操作符重载
    EncInt& operator=(int p_value);
    EncInt& operator=(float p_value);
    // 信号
    static void _bind_methods() {
        ClassDB::bind_method(D_METHOD("get_value"), &EncInt::get_value);
        ClassDB::bind_method(D_METHOD("set_value", "value"), &EncInt::set_value);
        ClassDB::bind_method(D_METHOD("get_type"), &EncInt::get_type);

        ADD_PROPERTY(PropertyInfo(Variant::INT, "value"), "set_value", "get_value");
        ADD_PROPERTY(PropertyInfo(Variant::STRING, "type"), "get_type", NULL);

        ADD_SIGNAL(MethodInfo("value_changed", PropertyInfo(Variant::INT, "value")));
        ADD_SIGNAL(MethodInfo("validation_failed", PropertyInfo(Variant::INT, "new_value"), PropertyInfo(Variant::STRING, "type")));
    }

    String get_type() const {
        return type;
    }
};

#endif // ENC_INT_H