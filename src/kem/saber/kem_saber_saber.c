#include <stdlib.h>

#include <oqs/kem_saber.h>

#ifdef OQS_ENABLE_KEM_saber_saber

OQS_KEM *OQS_KEM_saber_saber_new() {

	OQS_KEM *kem = malloc(sizeof(OQS_KEM));
	if (kem == NULL) {
		return NULL;
	}
	kem->method_name = OQS_KEM_alg_saber_saber;
	kem->alg_version = "https://github.com/KULeuven-COSIC/SABER/commit/14ede83f1ff3bcc41f0464543542366c68b55871";

	kem->claimed_nist_level = 3;
	kem->ind_cca = true;

	kem->length_public_key = OQS_KEM_saber_saber_length_public_key;
	kem->length_secret_key = OQS_KEM_saber_saber_length_secret_key;
	kem->length_ciphertext = OQS_KEM_saber_saber_length_ciphertext;
	kem->length_shared_secret = OQS_KEM_saber_saber_length_shared_secret;

	kem->keypair = OQS_KEM_saber_saber_keypair;
	kem->encaps = OQS_KEM_saber_saber_encaps;
	kem->decaps = OQS_KEM_saber_saber_decaps;

	return kem;
}

int PQCLEAN_SABER_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_SABER_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int PQCLEAN_SABER_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

OQS_API OQS_STATUS OQS_KEM_saber_saber_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (OQS_STATUS) PQCLEAN_SABER_CLEAN_crypto_kem_keypair(public_key, secret_key);
}
OQS_API OQS_STATUS OQS_KEM_saber_saber_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
	return (OQS_STATUS) PQCLEAN_SABER_CLEAN_crypto_kem_enc(ciphertext, shared_secret, public_key);
}
OQS_API OQS_STATUS OQS_KEM_saber_saber_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
	return (OQS_STATUS) PQCLEAN_SABER_CLEAN_crypto_kem_dec(shared_secret, ciphertext, secret_key);
}

#endif
