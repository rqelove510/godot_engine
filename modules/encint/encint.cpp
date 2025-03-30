#include "encint.h"

// 初始化全局 key
int64_t EncInt::_global_key = []() {
	std::random_device rd;
	std::mt19937_64 gen(rd());
	return gen();
}();

// 预计算旋转后的密钥
std::vector<int64_t> EncInt::_precomputed_rotated_keys;

void EncInt::_init_precomputed_keys() {
	constexpr int KEY_BITS = sizeof(_global_key) * 8;
	_precomputed_rotated_keys.reserve(16);
	for (int i = 0; i < 16; ++i) {
		int shift = i % KEY_BITS;
		int64_t rotated_key = (_global_key << shift) | (_global_key >> (KEY_BITS - shift));
		_precomputed_rotated_keys.push_back(rotated_key);
	}
}

// 加密实现
void EncInt::_encrypt_value(int64_t p_value) {
	if (_precomputed_rotated_keys.empty()) {
		_init_precomputed_keys();
	}
	int64_t temp = p_value ^ _m_instance_salt; // 盐值混合

	for (int i = 0; i < 16; ++i) {
		temp ^= _precomputed_rotated_keys[i];
	}

	_value = temp ^ (_m_instance_salt & _rdv);
}

int64_t EncInt::_decrypt_value() {
	if (_precomputed_rotated_keys.empty()) {
		_init_precomputed_keys();
	}
	int64_t temp = _value ^ (_m_instance_salt & _rdv);

	for (int i = 15; i >= 0; --i) {
		temp ^= _precomputed_rotated_keys[i];
	}

	return temp ^ _m_instance_salt; // 逆盐值混合
}

int EncInt::_calculate_checksum(int64_t p_value) const {
	int checksum = 0;
	std::byte *data = reinterpret_cast<std::byte *>(&p_value);
	for (size_t i = 0; i < sizeof(int64_t); ++i) {
		checksum += static_cast<unsigned char>(data[i]);
	}
	return checksum;
}

int64_t EncInt::get_value() {
	int64_t decrypted = _decrypt_value();
	int current_checksum = _calculate_checksum(decrypted);

	if (current_checksum != _checksum) {
		emit_signal("validation_failed", decrypted, _type);
		return 0;
	}
	return decrypted;
}

void EncInt::set_value(int64_t p_value) {
	_encrypt_value(p_value);
	_checksum = _calculate_checksum(p_value);
	emit_signal("value_changed", p_value);
}

// 默认构造函数
EncInt::EncInt() :
		_type("unknow_"), _value(0) {
	_m_instance_salt = generate_salt();
}

EncInt::EncInt(String type, int64_t init_value) {
	_type = type;
	_m_instance_salt = generate_salt();

	set_value(init_value);
}

// 静态工厂方法实现
Object *EncInt::create(const String &p_type, int64_t p_initial_value) {
	return memnew(EncInt(p_type, p_initial_value));
}

// 生成盐值
uint32_t EncInt::generate_salt() {
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(1, 9);
	return gen() | (dis(gen) * 0x2000000);
}

// 静态异或加密方法
int64_t EncInt::simple_enc(int64_t value) {
	return (value + 0x3a4d910f) ^ _rdv;
}

// 静态异或解密方法
int64_t EncInt::simple_dec(int64_t encrypted_value) {
	return (encrypted_value ^ _rdv) - 0x3a4d910f;
}

void EncInt::_bind_methods() {
	// 绑定 create 方法
	ClassDB::bind_static_method(
			"EncInt",
			D_METHOD("create", "type", "initial_value"),
			&EncInt::create);

	ClassDB::bind_method(D_METHOD("get_salt_value"), &EncInt::get_salt_value);
	ClassDB::bind_static_method("EncInt", D_METHOD("generate_salt"), &EncInt::generate_salt);

	ClassDB::bind_method(D_METHOD("get_value"), &EncInt::get_value);
	ClassDB::bind_method(D_METHOD("set_value", "value"), &EncInt::set_value);
	ClassDB::bind_method(D_METHOD("get_type"), &EncInt::get_type);

	ADD_PROPERTY(PropertyInfo(Variant::INT, "value"), "set_value", "get_value");
	ADD_PROPERTY(PropertyInfo(Variant::STRING, "type"), "", "get_type");

	ADD_SIGNAL(MethodInfo("value_changed", PropertyInfo(Variant::INT, "value")));
	ADD_SIGNAL(MethodInfo("validation_failed", PropertyInfo(Variant::INT, "new_value"), PropertyInfo(Variant::STRING, "type")));

	ClassDB::bind_static_method("EncInt", D_METHOD("simple_enc", "value"), &EncInt::simple_enc);
	ClassDB::bind_static_method("EncInt", D_METHOD("simple_dec", "encrypted_value"), &EncInt::simple_dec);
}
