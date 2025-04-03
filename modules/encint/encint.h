#ifndef ENCINT_H
#define ENCINT_H

#include "core/crypto/crypto_core.h"
#include "core/object/object.h"
#include "core/os/mutex.h"

class EncInt : public Object {
	GDCLASS(EncInt, Object);

private:
	EncInt()=default;

	Mutex mutex;

	String _type;
	uint64_t _value;
	uint64_t _checksum;
	uint64_t _rotation_num = 15;

	uint64_t _m_instance_salt = 0;
	uint64_t _gr_num;
	static const uint64_t _rdv = 0x1B5AC173;
	static uint64_t _global_key;
	Vector<uint64_t> _precomputed_rotated_keys;

	void _init_precomputed_keys();

	uint64_t _encrypt_value(uint64_t p_value) const;
	uint64_t _decrypt_value(uint64_t p_value) const;
	uint64_t _calculate_checksum(uint64_t value) const;

	bool _check_delta(uint64_t value);
	uint64_t _simple_cal(uint64_t p_value);
	uint64_t _get_rot_value(uint64_t value, bool clamp_idx = false);
	static uint64_t _restore_num(uint64_t enc_value, uint64_t salt, uint64_t rot);


protected:
	static void _bind_methods();

public:
	uint64_t get_value();
	void set_value(uint64_t p_value);
	String store_num();
	Array get_raw_data();

	String get_type() const { return _type; }
	void set_type(const String &p_type) {
		_type = p_type;
	}
	static uint64_t generate_big_randnum();

	static uint64_t simple_enc(uint64_t value, uint64_t salt_v = 0);
	static uint64_t simple_dec(uint64_t encrypted_value, uint64_t salt_v = 0);

	static String simple_enc_to_b64(uint64_t value, uint64_t salt_v = 0);
	static uint64_t simple_dec_from_b64(const String &b64_str, uint64_t salt_v = 0);

	static uint64_t restore_num(const String &base64_str);
	static uint64_t restore_num_from_raw_data(const Array &raw_data);

	static Object *create(uint64_t p_initial_value, const String &p_type);
	EncInt(uint64_t p_initial_value, String p_type);
	~EncInt() = default;
};

#endif // ENCINT_H
