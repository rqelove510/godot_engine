#include "encint.h"



// 加密实现
void EncInt::_encrypt_value(int64_t p_value) {
	int64_t temp = p_value ^ _m_instance_salt; // 盐值混合

	// 循环位移异或
	constexpr int KEY_BITS = sizeof(_global_key) * 8;
	for (int i = 0; i < 8; ++i) {
		int shift = i % KEY_BITS;
		int rotated_key = (_global_key << shift) | (_global_key >> (KEY_BITS - shift));
		temp ^= rotated_key;
	}

	_value = temp ^ (_m_instance_salt & _rdv);


}

int64_t EncInt::_decrypt_value() {
	int64_t temp = _value ^ (_m_instance_salt & _rdv);

	constexpr int KEY_BITS = sizeof(_global_key) * 8;
	for (int i = 8 - 1; i >= 0; --i) {
		int shift = i % KEY_BITS;
		int rotated_key = (_global_key << shift) | (_global_key >> (KEY_BITS - shift));
		temp ^= rotated_key;
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
// 默认构造函数
EncInt::EncInt() :
		_type("unknow_"), _value(0), _m_instance_salt(0) {}


EncInt::EncInt(String type, int64_t init_value, int64_t init_salt) {
	_type = type;

	if (init_salt == 0) {
		_m_instance_salt = generate_salt();
	} else {
		_m_instance_salt = init_salt;
	}
	
	set_value(init_value);
	
}

//void EncInt::_init(const String &p_type, int64_t p_initial_value, int64_t p_salt_value) {
//	_type = p_type;
//
//	if (p_salt_value == 0) {
//		_m_instance_salt = generate_salt();
//	} else {
//		_m_instance_salt = p_salt_value;
//	}
//
//	set_value(p_initial_value);
//}


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

// 静态工厂方法实现
Object *EncInt::create(const String &p_type, int64_t p_initial_value, int64_t p_salt_value) {
	return memnew(EncInt(p_type, p_initial_value, p_salt_value));
}


void EncInt::_bind_methods() {
		// 绑定 create 方法
	ClassDB::bind_static_method(
			"EncInt",
			D_METHOD("create", "type", "initial_value", "salt_value"),
			&EncInt::create);

	//ClassDB::bind_method(D_METHOD("_init", "type", "initial_value", "salt_value"), &EncInt::_init);

	ClassDB::bind_method(D_METHOD("get_salt_value"), &EncInt::get_salt_value);
	ClassDB::bind_static_method("EncInt", D_METHOD("generate_salt"), &EncInt::generate_salt);

	ClassDB::bind_method(D_METHOD("get_value"), &EncInt::get_value);
	ClassDB::bind_method(D_METHOD("set_value", "value"), &EncInt::set_value);
	ClassDB::bind_method(D_METHOD("get_type"), &EncInt::get_type);

	ADD_PROPERTY(PropertyInfo(Variant::INT, "value"), "set_value", "get_value");
	ADD_PROPERTY(PropertyInfo(Variant::STRING, "type"), "", "get_type");

	ADD_SIGNAL(MethodInfo("value_changed", PropertyInfo(Variant::INT, "value")));
	ADD_SIGNAL(MethodInfo("validation_failed", PropertyInfo(Variant::INT, "new_value"), PropertyInfo(Variant::STRING, "type")));
}
