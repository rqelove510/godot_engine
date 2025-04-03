#include "encint.h"
#include "core/os/os.h"
#include "core/os/time.h"

uint64_t EncInt::_global_key = []() {
	return 0;
}();

void EncInt::_init_precomputed_keys() {
	_precomputed_rotated_keys.resize(8);
	for (int i = 0; i < 8; ++i) {
		uint64_t rotated_key = (_m_instance_salt << i) | (_m_instance_salt >> (64 - i));
		_precomputed_rotated_keys.write[i] = rotated_key;
	}
}

String EncInt::store_num() {
	MutexLock lock(mutex);

	uint64_t encrypted_value_xor = _value;
	uint64_t salt_xor = _m_instance_salt ^ (_rdv + 0x2c9b);
	uint64_t rot_xor = _rotation_num ^ (_rdv + 0xb34a);
	uint64_t verify = (encrypted_value_xor ^ _rdv) ^ _global_key;

	PackedByteArray data;
	data.resize(32);

	for (int i = 0; i < 8; ++i) {
		data.write[i] = (encrypted_value_xor >> (i * 8)) & 0xFF;
		data.write[i + 8] = (salt_xor >> (i * 8)) & 0xFF;
		data.write[i + 16] = (rot_xor >> (i * 8)) & 0xFF;
		data.write[i + 24] = (verify >> (i * 8)) & 0xFF;
	}

	return CryptoCore::b64_encode_str(data.ptr(), data.size());
}

uint64_t EncInt::restore_num(const String &p_encoded) {
	const char *data = p_encoded.utf8().get_data();
	int data_len = p_encoded.length();

	int max_decoded_len = data_len * 3 / 4 + 1;
	PackedByteArray buf;
	buf.resize(max_decoded_len);

	size_t decoded_len = 0;
	Error err = CryptoCore::b64_decode(
			buf.ptrw(),
			buf.size(),
			&decoded_len,
			reinterpret_cast<const unsigned char *>(data),
			data_len);

	if (err != OK || decoded_len != 32) {
		return 0;
	}

	buf.resize(decoded_len);

	uint64_t encrypted_value = 0;
	uint64_t salt_xor = 0;
	uint64_t rot_xor = 0;
	uint64_t verify = 0;

	for (int i = 0; i < 8; ++i) {
		encrypted_value |= static_cast<uint64_t>(buf[i]) << (i * 8);
		salt_xor |= static_cast<uint64_t>(buf[i + 8]) << (i * 8);
		rot_xor |= static_cast<uint64_t>(buf[i + 16]) << (i * 8);
		verify |= static_cast<uint64_t>(buf[i + 24]) << (i * 8);
	}

	if (verify != ((encrypted_value ^ _rdv) ^ _global_key)) {
		return 0;
	}

	uint64_t rot_value = rot_xor ^ (_rdv + 0xb34a);
	uint64_t salt_value = salt_xor ^ (_rdv + 0x2c9b);

	return _restore_num(encrypted_value, salt_value, rot_value);
}

uint64_t EncInt::restore_num_from_raw_data(const Array &raw_data) {
	uint64_t encrypted_value = raw_data[0];
	uint64_t salt_value = raw_data[1];
	uint64_t rot_value = raw_data[2];
	uint64_t global_key = raw_data[3];
	return _restore_num(encrypted_value, salt_value, rot_value);
}

Array EncInt::get_raw_data() {
	MutexLock lock(mutex);
	Array lis;
	lis.resize(4);
	lis[0] = _value;
	lis[1] = _m_instance_salt;
	lis[2] = _rotation_num;
	lis[3] = _global_key;
	return lis;
}

uint64_t EncInt::_restore_num(uint64_t encrypted_value, uint64_t salt_value, uint64_t rot_value) {
	if (rot_value < 8) {
		uint64_t temp = encrypted_value ^ (_global_key & _rdv);

		for (int i = static_cast<int>(rot_value); i >= 0; --i) {
			uint64_t rotated_key = (salt_value << i) | (salt_value >> (64 - i));
			temp ^= rotated_key;
		}
		return (temp ^ salt_value) ^ ((salt_value << rot_value) | (salt_value >> (64 - rot_value)));
	} else {
		uint64_t loopcount = rot_value % 8;
		uint64_t xo_key = (salt_value << loopcount) | (salt_value >> (64 - loopcount));
		uint64_t shift = ((rot_value % 8) + 4) % 8;
		uint64_t parm_key = (salt_value << shift) | (salt_value >> (64 - shift));

		return simple_dec(encrypted_value, parm_key) ^ xo_key;
	}
}

uint64_t EncInt::_encrypt_value(uint64_t p_value) const {
	MutexLock lock(mutex);
	uint64_t temp = p_value ^ _m_instance_salt;
	uint64_t loopcount = (_rotation_num % 8) + 1;
	for (int i = 0; i < static_cast<int>(loopcount); ++i) {
		temp ^= _precomputed_rotated_keys[i];
	}
	return temp ^ (_global_key & _rdv);
}

uint64_t EncInt::_decrypt_value(uint64_t p_value) const {
	MutexLock lock(mutex);
	uint64_t temp = p_value ^ (_global_key & _rdv);
	uint64_t loopcount = _rotation_num % 8;
	for (int i = static_cast<int>(loopcount); i >= 0; --i) {
		temp ^= _precomputed_rotated_keys[i];
	}
	return temp ^ _m_instance_salt;
}

uint64_t EncInt::_calculate_checksum(uint64_t p_value) const {
	MutexLock lock(mutex);
	uint32_t checksum = 0;
	uint32_t *data32 = reinterpret_cast<uint32_t *>(&p_value);
	for (size_t i = 0; i < sizeof(uint64_t) / sizeof(uint32_t); ++i) {
		checksum += data32[i];
	}
	return checksum;
}

uint64_t EncInt::get_value() {
	MutexLock lock(mutex);
	uint64_t x_v = Time::get_singleton()->get_ticks_msec();

	if (_checksum != _calculate_checksum(_value)) {
		emit_signal("v_failed", -2, _type);//-1时间验证不过，-2和值验证不过，
		return 0;
	}

	uint64_t temp_key = 0;
	if (_check_delta(x_v)) {
		emit_signal("v_failed", -1, _type);
		return 0;
	}

	if (_rotation_num < 8) {
		uint64_t value = _decrypt_value(_value);
		temp_key = _precomputed_rotated_keys[_rotation_num];
		x_v = value ^ temp_key;
		return x_v;
	} else {
		temp_key = _precomputed_rotated_keys[_get_rot_value(_rotation_num, true)];
		x_v = simple_dec(_value, temp_key);
		return x_v ^ _precomputed_rotated_keys[_rotation_num % 8];
	}
}

void EncInt::set_value(uint64_t p_value) {
	uint64_t x_v = Time::get_singleton()->get_ticks_msec();
	MutexLock lock(mutex);
	_rotation_num = _get_rot_value(p_value);

	if (_check_delta(x_v)) {
		emit_signal("v_failed", -1, _type);
		return;
	}
	if (_rotation_num < 8) {
		_value = _encrypt_value(p_value ^ _precomputed_rotated_keys[_rotation_num]);
	} else {
		uint64_t temp_key = _precomputed_rotated_keys[_get_rot_value(_rotation_num, true)];
		_value = simple_enc(p_value ^ _precomputed_rotated_keys[_rotation_num % 8], temp_key);
	}
	_checksum = _calculate_checksum(_value);
	emit_signal("value_changed", p_value);

}

bool EncInt::_check_delta(uint64_t pri_time) {
	//_gr_num = (Math::rand() % 1000) + 0x128 + value;
	return Time::get_singleton()->get_ticks_msec() - pri_time > 100;
}

uint64_t EncInt::_simple_cal(uint64_t p_value) {
	return p_value + 0x74b1 ^ _rdv;
}

uint64_t EncInt::_get_rot_value(uint64_t value, bool clamp) {
	if (clamp) {
		return ((value % 8) + 4) % 8;
	}
	return (Math::rand() % 15) + 1;
}

EncInt::EncInt() :
		_value(0), _type("unknow_int") {
	if (_global_key == 0) {
		String mac_addr = OS::get_singleton()->get_mac_address();
		if (mac_addr == "") {
			mac_addr = OS::get_singleton()->get_unique_id();
		}
		mac_addr += "_ZHGAME";
		_global_key = mac_addr.hash() * 100 + 0x48;
	}
	_m_instance_salt = generate_big_randnum();
	_init_precomputed_keys();

	set_value(0);
}

EncInt::EncInt(uint64_t init_value, String type) {
	_type = type;
	if (_global_key == 0) {
		String mac_addr = OS::get_singleton()->get_mac_address();
		if (mac_addr == "") {
			mac_addr = OS::get_singleton()->get_unique_id();
		}
		mac_addr += "_ZHGAME";
		_global_key = mac_addr.hash() * 100 + 0x48;
	}
	_m_instance_salt = generate_big_randnum();
	_init_precomputed_keys();

	set_value(init_value);
}

Object *EncInt::create(uint64_t p_initial_value, const String &p_type) {
	return memnew(EncInt(p_initial_value, p_type));
}

uint64_t EncInt::generate_big_randnum() {
	uint64_t rand_digit = (Math::rand() % 9 + 1) * 1000000000ULL + Math::rand() % 999999999ULL;
	return rand_digit;
}

uint64_t EncInt::simple_enc(uint64_t value, uint64_t salt_v) {
	return (value + _global_key) ^ ((salt_v == 0) ? _rdv : salt_v);
}

uint64_t EncInt::simple_dec(uint64_t encrypted_value, uint64_t salt_v) {
	return (encrypted_value ^ ((salt_v == 0) ? _rdv : salt_v)) - _global_key;
}

String EncInt::simple_enc_to_b64(uint64_t value, uint64_t key) {
	uint64_t num_xor = simple_enc(value, key) ^ 0x7e213b1f;
	PackedByteArray data;
	data.resize(8);
	for (int i = 0; i < 8; ++i) {
		data.write[i] = (num_xor >> (i * 8)) & 0xFF;
	}
	return CryptoCore::b64_encode_str(data.ptr(), data.size());
}

uint64_t EncInt::simple_dec_from_b64(const String &b64_str, uint64_t key) {
	const char *data = b64_str.utf8().get_data();
	int data_len = b64_str.length();
	int max_decoded_len = data_len * 3 / 4 + 1;
	PackedByteArray buf;
	buf.resize(max_decoded_len);

	size_t decoded_len = 0;
	Error err = CryptoCore::b64_decode(
			buf.ptrw(),
			buf.size(),
			&decoded_len,
			reinterpret_cast<const unsigned char *>(data),
			data_len);

	if (err != OK || decoded_len != 8) {
		return 0;
	}

	buf.resize(decoded_len);
	uint64_t num_xor = 0;
	for (int i = 0; i < 8; ++i) {
		num_xor |= static_cast<uint64_t>(buf[i]) << (i * 8);
	}

	return simple_dec(num_xor ^ 0x7e213b1f, key);
}

void EncInt::_bind_methods() {
	ClassDB::bind_static_method(
			"EncInt",
			D_METHOD("create", "initial_value", "type"),
			&EncInt::create, DEFVAL(0), DEFVAL("unknow_int"));

	ClassDB::bind_method(D_METHOD("get_value"), &EncInt::get_value);
	ClassDB::bind_method(D_METHOD("set_value", "value"), &EncInt::set_value);
	ClassDB::bind_method(D_METHOD("get_type"), &EncInt::get_type);
	ClassDB::bind_method(D_METHOD("set_type"), &EncInt::set_type);

	ClassDB::bind_method(D_METHOD("store_num"), &EncInt::store_num);

	ClassDB::bind_method(D_METHOD("get_raw_data"), &EncInt::get_raw_data);

	ADD_PROPERTY(PropertyInfo(Variant::INT, "value"), "set_value", "get_value");
	ADD_PROPERTY(PropertyInfo(Variant::STRING, "type"), "set_type", "get_type");

	ADD_SIGNAL(MethodInfo("value_changed", PropertyInfo(Variant::INT, "value")));
	ADD_SIGNAL(MethodInfo("v_failed", PropertyInfo(Variant::INT, "new_value"), PropertyInfo(Variant::STRING, "type")));

	ClassDB::bind_static_method("EncInt", D_METHOD("generate_big_randnum"), &EncInt::generate_big_randnum);
	ClassDB::bind_static_method("EncInt", D_METHOD("simple_enc", "value", "salt_v"), &EncInt::simple_enc, DEFVAL(0));
	ClassDB::bind_static_method("EncInt", D_METHOD("simple_dec", "encrypted_value", "salt_v"), &EncInt::simple_dec, DEFVAL(0));
	ClassDB::bind_static_method("EncInt", D_METHOD("restore_num", "p_encoded"), &EncInt::restore_num);
	ClassDB::bind_static_method("EncInt", D_METHOD("restore_num_from_raw_data", "raw_data"), &EncInt::restore_num_from_raw_data);

	ClassDB::bind_static_method("EncInt", D_METHOD("simple_enc_to_b64", "value", "salt_v"), &EncInt::simple_enc_to_b64, DEFVAL(0));
	ClassDB::bind_static_method("EncInt", D_METHOD("simple_dec_from_b64", "b64_str", "salt_v"), &EncInt::simple_dec_from_b64, DEFVAL(0));
}
