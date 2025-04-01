#include "encint.h"
#include "core/os/time.h"

uint64_t EncInt::_global_key = []()
{
	return 0;
}();

Vector<uint64_t> EncInt::_precomputed_rotated_keys;

void EncInt::_init_precomputed_keys() {
	constexpr int KEY_BITS = sizeof(_global_key) * 8;
	_precomputed_rotated_keys.resize(8);
	for (int i = 0; i < 8; ++i) {
		int shift = i % KEY_BITS;
		uint64_t rotated_key = (_global_key << shift) | (_global_key >> (KEY_BITS - shift));
		//if (i < _precomputed_rotated_keys.size()) {
			_precomputed_rotated_keys.write[i] = rotated_key;
		//}
	}
}

Dictionary EncInt::store_num() {
	Dictionary m_data;
	m_data["encrypt_value"] = Variant(_value);
	m_data["global_key"] = Variant(_global_key);
	m_data["salt_value"] = Variant(_m_instance_salt);

	return m_data;
}

uint64_t EncInt::restore_num(uint64_t encrypt_value, uint64_t global_key, uint64_t salt_value) {
	uint64_t temp = encrypt_value ^ (salt_value & _rdv); // 添加此步骤
	for (int i = 7; i >= 0; --i) { // 逆序异或
		int shift = i % 64;
		uint64_t rotated_key = (global_key << shift) | (global_key >> (64 - shift));
		temp ^= rotated_key;
	}
	return temp ^ salt_value;
}

void EncInt::_encrypt_value(uint64_t p_value) {
	uint64_t temp = p_value ^ _m_instance_salt; 
	for (int i = 0; i < 8; ++i) {
		temp ^= _precomputed_rotated_keys[i];
	}
	_value = temp ^ (_m_instance_salt & _rdv);
}

uint64_t EncInt::_decrypt_value() {
	uint64_t temp = _value ^ (_m_instance_salt & _rdv);
	for (int i = 7; i >= 0; --i) {
		temp ^= _precomputed_rotated_keys[i];
	}
	return temp ^ _m_instance_salt; 
}

uint64_t EncInt::_calculate_checksum(uint64_t p_value) const {

	uint32_t checksum = 0;
	uint32_t *data32 = reinterpret_cast<uint32_t *>(&p_value);

	for (size_t i = 0; i < sizeof(uint64_t) / sizeof(uint32_t); ++i) {
		checksum += data32[i];
	}
	return checksum;
}

uint64_t EncInt::_get_value2(uint64_t value, uint64_t value2) {
	uint64_t mask_v = _rand_num ^ value2;
	if (value > value2) {
		value2 += _checksum + value;
		return _get_value2(value, value2);
	}
	if (simple_enc(mask_v) + _rand_num > 32) {
		//读保护
		mask_v = _decrypt_value() + _rdv;
 	}
	uint64_t d = _calculate_checksum(mask_v);
	if (d != _checksum) {
		emit_signal("v_failed", mask_v - _rdv, _type);
		return 0;
	}
	return mask_v;
}

uint64_t EncInt::get_value() {
	//uint64_t start_t = 0x16b2;
	//uint64_t a = 32;
	//_rand_num = 0;

	//uint64_t sum = _calculate(a + start_t);//时间起点

	//for (uint8_t i = 0; i < 6; ++i) {
	//	a += (i + 2) * 12 - 5;
	//	if (i > 0 and a % 3 == 0) { 
	//		a = simple_enc(start_t);
	//	} else {
	//		if (i < 3) {
	//			if (_rdv > 32) {
	//				a *= 2 + _checksum;
	//			}
	//		}
	//		start_t += 128;
	//	}

	//	if (i == 3) {
	//		a += _checksum;
	//		if (_rdv > start_t) {
	//			start_t = simple_enc(_checksum);
	//		}

	//		if (_rand_num < 64 or Time::get_singleton()->get_ticks_msec() - sum > 200) {
	//			emit_signal("v_failed", -1, _type);
	//			return 0;
	//		} else {
	//			sum = _get_value2(start_t, i);//关键返回，已经解密，  值 ^ _rdv
	//			if (sum == 0) {
	//				return 0;
	//			} else {
	//				sum = _simple_cal(sum - _rand_num);//进一步加密结果，等待解密流程  ^_rvd ->  -0x74b1-> +rand_num -> -_rdv 
	//			}
	//		}
	//	} else {//非3，   0，1，2，4，5
	//		start_t += _rand_num;
	//		if (i > 0 and i % 4 == 0) {
	//			sum ^= _rdv;
	//		}
	//		if (i == 5) {
	//			start_t = 0;
	//			sum -= - 0x741;
	//		}
	//	}			
	//}
	//if (sum += _rand_num > start_t) {
	//	return sum - _rdv;
	//}
	//return 0;

	uint64_t value = _decrypt_value();
	if (_checksum != _calculate_checksum(value)) {
		emit_signal("v_failed", value, _type);
	}
	return value;
}

uint64_t EncInt::_calculate(uint64_t value) {
	uint64_t a = 16 + value;
	uint64_t temp = 1024 * 8;
	for (uint32_t i = 8; i > 0; --i) {
		temp += i;
		if (i * 8 > _checksum) {
			temp = (a + i) << 2;
		} else {
			value += (16 + 2 * 4);
		}
		value += 128;
		if (i == 1) {
			value += _checksum;
			a = 0;
			_rand_num = Math::rand() % 10000 + 65;
		}
	}
	if ((value % 1245) + 1 > a) {
		temp = Time::get_singleton()->get_ticks_msec();
	}

	return temp;
}

uint64_t EncInt::_simple_cal(uint64_t p_value) {
	return p_value + 0x74b1 ^ _rdv;
}

void EncInt::set_value(uint64_t p_value) {
	//uint64_t temp = p_value + _rdv;
	//uint64_t t = _simple_cal(p_value);
	//uint64_t start_t = p_value + 128;
	//uint64_t x_v = 2048;

	//if (start_t > p_value) {
	//	_rand_num = 32;
	//	x_v += simple_enc(temp ^ (_checksum * 2));//还原顺序 - 2048，simple_dec, ^_checksum*2 ,-rdv;
	//}
	//
	//for (uint8_t i = 7; i > 0; --i) {
	//	t += i * 32;
	//	uint32_t b = 32;

	//	if (i > 3) {
	//		temp += i * b;
	//		x_v -= b * 8;
	//	} else if (i == 1) {
	//		if (_rdv > b) {
	//			//t = 256;
	//			x_v = simple_dec(x_v - 1024);
	//		}
	//		b = _rand_num;

	//	} else if(i%2==1) {
	//		start_t = _calculate(p_value);
	//	}

	//	if (b > 32) {
	//		t = x_v ^ (_checksum * 2);
	//		temp = _calculate_checksum(t) ^ _rdv;// 计算和值用的是 (真实 + _rdv)
	//	}
	//}

	//if (_rand_num < 64 or Time::get_singleton()->get_ticks_msec() - start_t > 256) {
	//	emit_signal("v_failed", -2, _type);
	//	return;
	//}

	//_checksum = _rand_num;

	//if (_rand_num % 3 == 0) {
	//	if (start_t > _rand_num) {
	//		start_t = 0;
	//	} else {
	//		t = start_t ^ p_value;
	//	}
	//	temp ^= _rdv; //和值
	//} else {
	//	_checksum = temp ^ _rdv;
	//	emit_signal("value_changed", p_value);
	//}

	//if (t > _rdv) {
	//	if (start_t == 0) {
	//		emit_signal("value_changed", p_value);
	//		_checksum = temp;
	//	}
	//	//写保护
	//	_encrypt_value(t - _rdv);
	//	return;
	//} else {
	//	for (uint8_t i = 250; i > 0; --i) {
	//		t ^= simple_enc(p_value);
	//	}
	//}

	//for (uint8_t i = 250; i > 0; --i) {
	//	t ^= simple_dec(p_value);
	//	temp ^= _rdv + t;
	//}
	//return;


	_encrypt_value(p_value);
	_checksum = _calculate_checksum(p_value);
	emit_signal("value_changed", p_value);
}

EncInt::EncInt() :
		_value(0), _type("unknow_") {
	if (_global_key == 0) {
		_global_key = generate_big_randnum();
	}
	_init_precomputed_keys();
	_m_instance_salt = generate_big_randnum();

	set_value(0);
}
//
EncInt::EncInt(uint64_t init_value, String type) {
	_type = type;
	if (_global_key == 0) {
		_global_key = generate_big_randnum();
	}
	_init_precomputed_keys();
	_m_instance_salt = generate_big_randnum();

	set_value(init_value);
}

RefCounted *EncInt::create(uint64_t p_initial_value, const String &p_type) {
	return memnew(EncInt(p_initial_value, p_type));
}

uint64_t EncInt::generate_big_randnum() {
	uint64_t rand_digit = (Math::rand() % 9 + 1) * 1000000000ULL + Math::rand() % 999999999ULL;
	return rand_digit;
}

uint64_t EncInt::simple_enc(uint64_t value, uint64_t salt_v) {
	return (value + _global_key) ^ ((salt_v == 0)?_rdv:salt_v);
}

uint64_t EncInt::simple_dec(uint64_t encrypted_value, uint64_t salt_v) {
	return (encrypted_value ^ ((salt_v == 0) ? _rdv : salt_v)) - _global_key;
}

void EncInt::_bind_methods() {
	ClassDB::bind_static_method(
			"EncInt",
			D_METHOD("create", "initial_value", "type"),
			&EncInt::create, DEFVAL(0), DEFVAL("unknow_int"));

	ClassDB::bind_method(D_METHOD("get_value"), &EncInt::get_value);
	ClassDB::bind_method(D_METHOD("set_value", "value"), &EncInt::set_value);
	ClassDB::bind_method(D_METHOD("get_type"), &EncInt::get_type);
	ClassDB::bind_method(D_METHOD("store_num"), &EncInt::store_num);


	ADD_PROPERTY(PropertyInfo(Variant::INT, "value"), "set_value", "get_value");
	ADD_PROPERTY(PropertyInfo(Variant::STRING, "type"), "", "get_type");

	ADD_SIGNAL(MethodInfo("value_changed", PropertyInfo(Variant::INT, "value")));
	ADD_SIGNAL(MethodInfo("v_failed", PropertyInfo(Variant::INT, "new_value"), PropertyInfo(Variant::STRING, "type")));

	ClassDB::bind_static_method("EncInt", D_METHOD("generate_big_randnum"), &EncInt::generate_big_randnum);
	ClassDB::bind_static_method("EncInt", D_METHOD("simple_enc", "value", "salt_v"), &EncInt::simple_enc, DEFVAL(0));
	ClassDB::bind_static_method("EncInt", D_METHOD("simple_dec", "encrypted_value", "salt_v"), &EncInt::simple_dec, DEFVAL(0));
	ClassDB::bind_static_method("EncInt", D_METHOD("restore_num", "encrypted_value", "global_value", "salt_value"), &EncInt::restore_num);
}
