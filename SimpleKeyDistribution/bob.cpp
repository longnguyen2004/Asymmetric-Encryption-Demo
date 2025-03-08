#pragma once

#include "common.h"
#include "main.h"
#include <utility>
#include <iostream>
#include <string>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>

using namespace CryptoPP;

void main_bob()
{
	AutoSeededRandomPool rng;
	std::cout << "------------ Bob ------------\n";

	// Get Alice's public key
	std::cout << "Alice's public key: ";
	std::string pubKeyStr;
	std::getline(std::cin >> std::ws, pubKeyStr);
	std::cout << '\n';
	
	std::string pubKeyEncoded;
	RSA::PublicKey pubKey;
	StringSource pubKeySource(
		pubKeyStr, true,
		new HexDecoder()
	);
	pubKey.Load(pubKeySource);

	// Generate AES symmetric key
	auto aesKey = generateAES256Key();
	std::string aesKeyStr;
	StringSource(
		aesKey.data(), aesKey.size(), true,
		new HexEncoder(
			new StringSink(aesKeyStr)
		)
	);
	std::cout << "Generated symmetric key: " << aesKeyStr << '\n';

	// Encrypt the symmetric key
	std::string aesKeyEncrypted;
	RSAES_OAEP_SHA256_Encryptor encryptor(pubKey);
	ArraySource(
		aesKey.data(), aesKey.size(), true,
		new PK_EncryptorFilter(
			rng, encryptor,
			new HexEncoder(
				new StringSink(aesKeyEncrypted)
			)
		)
	);
	std::cout << "Encrypted symmetric key: " << aesKeyEncrypted << '\n';
	std::cout << "Send this to Alice!\n";
}
