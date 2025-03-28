#ifndef ENCINT_H
#define ENCINT_H

#include "core/object/object.h"
#include "core/string/ustring.h"
#include "core/crypto/crypto_core.h"


class EncInt : public Object {
    GDCLASS(EncInt, Object);

	static int _encryption_key;
	static bool _key_initialized;
	String _type = "unknow_eint";

private:
	int _value;
	int _checksum;
	bool is_validation;

	static void _initialize_key();
	int _encrypt(int p_value) const;
	int _decrypt(int p_value) const;
	int _calculate_checksum(int p_value) const;

protected:
	static void _bind_methods();

public:
    int get_value() const;
    void set_value(int p_value);
	String get_type() const;
	void set_type(int p_type){};


	EncInt() = default; //{ EncInt("unknow_eint"); }
	EncInt(String p_type, int p_initial_value = 0, bool p_validation_enabled = false);
	~EncInt() = default;
};

#endif // ENCINT_H
