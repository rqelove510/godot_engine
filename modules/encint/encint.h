#ifndef ENCINT_H
#define ENCINT_H

#include "core/crypto/crypto_core.h"
#include "core/object/object.h"


class EncInt : public Object {
	GDCLASS(EncInt, Object);


private:
	EncInt();

	String _type;
	int64_t _value;
	int _checksum;

	uint32_t _m_instance_salt = 0;
	uint32_t _rdv = 0x1B5AC173; //扰动值
	int64_t _global_key = 0x1234567890123456;


    // 私有方法
	void _encrypt_value(int64_t p_value);
	int64_t _decrypt_value();
	int _calculate_checksum(int64_t value) const;

protected:
	static void _bind_methods();


public:
	// 获取加密后的值
	int64_t get_value();
	// 设置加密后的值
	void set_value(int64_t p_value);
	// 获取类型
	String get_type() const { return _type; }

	uint32_t get_salt_value() { return _m_instance_salt; }


	static uint32_t generate_salt() {
		Math::randomize();
		return rand() | ((rand() % 9 + 1) * 0x10000000);
	}
	static Object *create(const String &p_type, int64_t p_initial_value, int64_t p_salt_value);


	// 默认带参构造函数
	EncInt(String p_type, int64_t p_initial_value, int64_t salt_value);

	// 析构函数
	~EncInt() = default;
};

#endif // ENCINT_H
