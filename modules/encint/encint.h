#ifndef ENCINT_H
#define ENCINT_H

//#include "core/crypto/crypto_core.h"
#include "core/object/ref_counted.h"

class EncInt : public RefCounted {
	GDCLASS(EncInt, RefCounted);

private:
	EncInt();

	String _type;
	uint64_t _value;
	uint32_t _checksum;
	uint32_t _rand_num;

	uint64_t _m_instance_salt = 0;
	const static uint64_t _rdv = 0x1B5AC173;
	static uint64_t _global_key;
	static Vector<uint64_t> _precomputed_rotated_keys;

	//// 私有方法
	void _encrypt_value(uint64_t p_value);
	uint64_t _decrypt_value();
	uint64_t _calculate_checksum(uint64_t value) const;
	void _init_precomputed_keys();
	uint64_t _calculate(uint64_t value);
	uint64_t _simple_cal(uint64_t p_value);
	uint64_t _get_value2(uint64_t value, uint64_t value2);

protected:
	static void _bind_methods();

public:
	uint64_t get_value();
	void set_value(uint64_t p_value);
	String get_type() const { return _type; }
	Dictionary store_num();

	//// 生成一个10的饱和大随机值。
	static uint64_t generate_big_randnum();
	// 新增静态异或加密方法
	static uint64_t simple_enc(uint64_t value, uint64_t salt_v = 0);
	// 新增静态异或解密方法
	static uint64_t simple_dec(uint64_t encrypted_value, uint64_t salt_v = 0);
	static uint64_t restore_num(uint64_t enc_v, uint64_t glo_v, uint64_t salt_v);

	static RefCounted *create(uint64_t p_initial_value, const String &p_type);
	EncInt(uint64_t p_initial_value, String p_type);
	~EncInt() = default;
};

#endif // ENCINT_H
