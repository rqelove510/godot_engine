#ifndef ENCINT_H
#define ENCINT_H

#include "core/crypto/crypto_core.h"
#include "core/object/object.h"
#include <random>
#include <vector>

class EncInt : public Object {
	GDCLASS(EncInt, Object);

private:
	EncInt();

	String _type;
	int64_t _value;
	int _checksum;

	uint32_t _m_instance_salt = 0;
	const static uint32_t _rdv = 0x1B5AC173; // 扰动值
	static int64_t _global_key;
	static std::vector<int64_t> _precomputed_rotated_keys;

	// 私有方法
	void _encrypt_value(int64_t p_value);
	int64_t _decrypt_value();
	int _calculate_checksum(int64_t value) const;
	void _init_precomputed_keys();

protected:
	static void _bind_methods();

public:
	int64_t get_value();
	void set_value(int64_t p_value);
	String get_type() const { return _type; }

	// 获取盐值
	uint32_t get_salt_value() const { return _m_instance_salt; }
	static uint32_t generate_salt();

	static Object *create(const String &p_type, int64_t p_initial_value);

	// 默认带参构造函数
	EncInt(String p_type, int64_t p_initial_value);

	// 析构函数
	~EncInt() = default;

	// 新增静态异或加密方法
	static int64_t simple_enc(int64_t value);
	// 新增静态异或解密方法
	static int64_t simple_dec(int64_t encrypted_value);
};

#endif // ENCINT_H
