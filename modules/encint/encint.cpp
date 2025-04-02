#include "encint.h"
#include "core/os/os.h"
#include "core/os/time.h"

//#include "core/core_bind.h"

uint64_t EncInt::_global_key = []() {
	return 0;
}();

void EncInt::_init_precomputed_keys() {
	constexpr int KEY_BITS = sizeof(_m_instance_salt) * 8;
	_precomputed_rotated_keys.resize(16);
	for (int i = 0; i < 16; ++i) {
		int shift = i % KEY_BITS;
		uint64_t rotated_key = (_m_instance_salt << shift) | (_m_instance_salt >> (KEY_BITS - shift));
		_precomputed_rotated_keys.write[i] = rotated_key;
	}
}

String EncInt::store_num() {
	uint64_t encrypted_value_xor = _value;
	uint64_t salt_xor = _m_instance_salt ^ (_rdv + 0x2c9b);
	uint64_t rot_xor = _rotation_num ^ (_rdv + 0xb34a);

	PackedByteArray data;
	data.resize(24);

	for (int i = 0; i < 8; ++i) {
		data.write[i] = (encrypted_value_xor >> (i * 8)) & 0xFF;
		data.write[i + 8] = (salt_xor >> (i * 8)) & 0xFF;
		data.write[i + 16] = (rot_xor >> (i * 8)) & 0xFF;
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

	if (err != OK || decoded_len != 24) {
		return 0;
	}

	buf.resize(decoded_len);

	uint64_t encrypted_value = 0;
	uint64_t salt_xor = 0;
	uint64_t rot_xor = 0;

	for (int i = 0; i < 8; ++i) {
		encrypted_value |= static_cast<uint64_t>(buf[i]) << (i * 8);
		salt_xor |= static_cast<uint64_t>(buf[i + 8]) << (i * 8);
		rot_xor |= static_cast<uint64_t>(buf[i + 16]) << (i * 8);
	}

	// 确保异或操作先执行
	uint64_t rot_value = rot_xor ^ (_rdv + 0xb34a);
	uint64_t salt_value = salt_xor ^ (_rdv + 0x2c9b);

	uint64_t temp = encrypted_value ^ (_global_key & _rdv);

	int loop_count = static_cast<int>(rot_value) % 16; // 假设最多循环16次

	for (int i = loop_count; i >= 0; --i) {
		int shift = i % 64;
		uint64_t rotated_key = (salt_value << shift) | (salt_value >> (64 - shift));
		temp ^= rotated_key;
	}
	return temp ^ salt_value;
}

Array EncInt::test() {
	Array lis;
	lis.resize(2);
	lis[0] = _value;
	lis[1] = _m_instance_salt;
	return lis;
}

void EncInt::_encrypt_value(uint64_t p_value) {
	uint64_t temp = p_value ^ _m_instance_salt;
	for (int i = 0; i < _rotation_num; ++i) {
		temp ^= _precomputed_rotated_keys[i];
	}
	_value = temp ^ (_global_key & _rdv);
}

uint64_t EncInt::_decrypt_value() {
	uint64_t temp = _value ^ (_global_key & _rdv);
	for (int i = _rotation_num - 1; i >= 0; --i) {
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
	return (Math::rand() % 14) + 3;
	//uint64_t mask_v = _rand_num ^ value2;
	//if (value > value2) {
	//	value2 += _checksum + value;
	//	return _get_value2(value, value2);
	//}
	//if (simple_enc(mask_v) + _rand_num > 32) {
	//	//读保护
	//	mask_v = _decrypt_value() + _rdv;
	//}
	//uint64_t d = _calculate_checksum(mask_v);
	//if (d != _checksum) {
	//	emit_signal("v_failed", mask_v - _rdv, _type);
	//	return 0;
	//}
	//return mask_v;
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
		return 0;
	}
	return value;
}

void EncInt::set_value(uint64_t p_value) {
	_rand_num = 32;
	uint64_t temp = simple_enc(p_value);
	uint64_t start_t = p_value + 128;
	uint64_t x_v = 2048;
	
	if ((temp % _rand_num) < x_v) {
		uint64_t temp2 = 64 << 2;
		for (int i = 0; i < 5; i++) {
			//1.无意义，2:x_v - 1024，3：时间校验，
			temp2 += p_value;
			if (_rand_num > 128) {
				temp += 1024 ^ _rand_num;
				if (i % 2 == 0 and i < 4) {
					x_v -= 1024; //开始还原加密
				}
				temp2 += i + p_value / 2;
			} else {//1.i==0进入此分支，完成 x_v的第一段值计算。
				temp = p_value + (_rand_num << 4);
				//时间校验初始化；
				start_t = _calculate(start_t + p_value);
			}
			uint16_t deta_v = 128;
			if (i ==4) {
				_rand_num = 32;
				temp = _rdv ^ _rand_num;
			} else {
				if (i > 0) {
					deta_v += 128;
					if (i == 2) {
						temp2 ^= (_rand_num + 0x2af1);
						x_v -= 1024; //第2次减1024
					}
					if (i % 3 == 0) {
						//时间校验
						if (_rand_num < 64 or Time::get_singleton()->get_ticks_msec() - start_t > deta_v) {
							emit_signal("v_failed", -2, _type);
							return;
						}
						//3 start_t交换关键数据到手
						start_t = simple_enc(x_v ^ _rdv);
					}
				} else {
					x_v += _simple_cal(temp);//2. i==0 -> 完成初次加密，注意temp不可被修改
				}
				temp2 += deta_v;
			}
		}
		if ((temp ^ _rand_num) == _rdv) {
			//此处新函数处调用，设置旋转值后调用真正加密函数


			x_v = simple_dec(start_t) - 0x74b1;
			uint64_t result = x_v - (_rand_num << 4);

			_rotation_num = _get_value2(p_value, temp2); //取旋转数；

			_encrypt_value(result);
			_checksum = _calculate_checksum(p_value);
			emit_signal("value_changed", p_value);
		}

	}
	
	//
	//
	//_encrypt_value(p_value);
	//_checksum = _calculate_checksum(p_value);
	//emit_signal("value_changed", p_value);
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
			_rand_num = (Math::rand() % 10000) + 0x128;
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

EncInt::EncInt() :
		_value(0), _type("unknow_") {
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
		// 这里可以添加错误处理逻辑
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
	ClassDB::bind_method(D_METHOD("store_num"), &EncInt::store_num);

	
	ClassDB::bind_method(D_METHOD("test"), &EncInt::test);


	ADD_PROPERTY(PropertyInfo(Variant::INT, "value"), "set_value", "get_value");
	ADD_PROPERTY(PropertyInfo(Variant::STRING, "type"), "", "get_type");

	ADD_SIGNAL(MethodInfo("value_changed", PropertyInfo(Variant::INT, "value")));//, PropertyInfo(Variant::STRING, "type")
	ADD_SIGNAL(MethodInfo("v_failed", PropertyInfo(Variant::INT, "new_value"), PropertyInfo(Variant::STRING, "type")));

	ClassDB::bind_static_method("EncInt", D_METHOD("generate_big_randnum"), &EncInt::generate_big_randnum);
	ClassDB::bind_static_method("EncInt", D_METHOD("simple_enc", "value", "salt_v"), &EncInt::simple_enc, DEFVAL(0));
	ClassDB::bind_static_method("EncInt", D_METHOD("simple_dec", "encrypted_value", "salt_v"), &EncInt::simple_dec, DEFVAL(0));
	ClassDB::bind_static_method("EncInt", D_METHOD("restore_num", "p_encoded"), &EncInt::restore_num);

	ClassDB::bind_static_method("EncInt", D_METHOD("simple_enc_to_b64", "value", "salt_v"), &EncInt::simple_enc_to_b64, DEFVAL(0));
	ClassDB::bind_static_method("EncInt", D_METHOD("simple_dec_from_b64", "b64_str", "salt_v"), &EncInt::simple_dec_from_b64, DEFVAL(0));

}
