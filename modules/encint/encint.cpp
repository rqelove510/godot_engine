#include "encint.h"

int EncInt::_encryption_key = 123456789;
bool EncInt::_key_initialized = false;


EncInt::EncInt(String p_type, int p_initial_value, bool p_validation_enabled) {
	_type = p_type;
	_initialize_key();
	is_validation = p_validation_enabled;
	set_value(p_initial_value);
}

void EncInt::_initialize_key() {
	if (!_key_initialized) {
		static CryptoCore::RandomGenerator rng;
		if (rng.init() != OK) {
			ERR_FAIL_MSG("Failed to initialize random number generator");
		}

		PackedByteArray iv;
		iv.resize(16);
		if (rng.get_random_bytes(iv.ptrw(), 16) != OK) {
			ERR_FAIL_MSG("Failed to generate random bytes");
		}

		memcpy(&_encryption_key, iv.ptr(), sizeof(int));
		print_line(vformat("这里生成的密钥是:%d", _encryption_key));
		_key_initialized = true;
	}
}

int EncInt::_encrypt(int p_value) const {
	return p_value ^ _encryption_key;
}

int EncInt::_decrypt(int p_value) const {
	return p_value ^ _encryption_key;
}

int EncInt::_calculate_checksum(int p_value) const {
	int checksum = 0;
	char *data = reinterpret_cast<char *>(&p_value);
	for (size_t i = 0; i < sizeof(int); ++i) {
		checksum += static_cast<unsigned char>(data[i]);
	}
	return checksum;
}

int EncInt::get_value() const {
	int decrypted = _decrypt(_value);
	int current_checksum = _calculate_checksum(decrypted);
	print_line(vformat("get_value.原始值:%d, checksum:%d", _value, current_checksum));

	if (current_checksum != _checksum) {
		const_cast<EncInt *>(this)->emit_signal("validation_failed", decrypted, _type);
	}
	return decrypted;
}

void EncInt::set_value(int p_value) {
	_value = _encrypt(p_value);
	_checksum = _calculate_checksum(p_value);
	emit_signal("value_changed", p_value);
}

String EncInt::get_type() const {
	return _type;
}

void EncInt::_bind_methods() {
	ClassDB::bind_method(D_METHOD("get_value"), &EncInt::get_value);
	ClassDB::bind_method(D_METHOD("set_value", "value"), &EncInt::set_value);
	ClassDB::bind_method(D_METHOD("get_type"), &EncInt::get_type);

	ADD_PROPERTY(PropertyInfo(Variant::INT, "value"), "set_value", "get_value");
	ADD_PROPERTY(PropertyInfo(Variant::STRING, "type"), "set_type", "get_type");

	ADD_SIGNAL(MethodInfo("value_changed", PropertyInfo(Variant::INT, "value")));
	ADD_SIGNAL(MethodInfo("validation_failed", PropertyInfo(Variant::INT, "new_value"), PropertyInfo(Variant::STRING, "type")));
}
