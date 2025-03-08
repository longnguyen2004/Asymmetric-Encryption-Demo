#include "common.h"
#include <cryptopp/osrng.h>

using namespace CryptoPP;

#define RSA_KEY_SIZE 4096u

std::pair<RSA::PrivateKey, RSA::PublicKey> generateRSAKeyPair()
{
	AutoSeededRandomPool rng;
	RSA::PrivateKey privKey;
	privKey.Initialize(rng, RSA_KEY_SIZE, 65537);
	RSA::PublicKey pubKey(privKey);
	return { privKey, pubKey };
}

SecByteBlock generateAES256Key()
{
	AutoSeededRandomPool rng;
	SecByteBlock key(32);
	rng.GenerateBlock(key, key.size());
	return key;
}
