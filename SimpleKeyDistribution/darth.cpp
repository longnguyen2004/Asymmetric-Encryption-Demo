#include "common.h"
#include "main.h"
#include <utility>
#include <iostream>
#include <string>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>

using namespace CryptoPP;

void main_darth()
{
	AutoSeededRandomPool rng;

	std::cout << "------------ Darth ------------\n";

	// Generate public-private key pair
	std::cout << "Generating public-private key pair\n";
	auto [privKey, pubKey] = generateRSAKeyPair();
	RSA::PublicKey pubKeyAlice;
	{
		// Get Alice's public key
		std::cout << "Alice's public key: ";
		std::string pubKeyStr;
		std::getline(std::cin >> std::ws, pubKeyStr);
		std::cout << '\n';

		StringSource pubKeySource(
			pubKeyStr, true,
			new HexDecoder()
		);
		pubKeyAlice.Load(pubKeySource);
	}

	// Encode the public key
	std::string pubKeyStr;
	HexEncoder pubKeyEncoder(new StringSink(pubKeyStr));
	pubKey.Save(pubKeyEncoder);
	std::cout << "Darth's public key: " << pubKeyStr << '\n';
	std::cout << "Send this to Bob!\n";
	std::cout << '\n';

	// Get the message with the symmetric key from Bob
	std::cout << "Bob's private key message: ";
	std::string symKeyMessageStr;
	std::getline(std::cin >> std::ws, symKeyMessageStr);
	std::string symKeyMessage;
	StringSource(
		symKeyMessageStr, true,
		new HexDecoder(
			new StringSink(symKeyMessage)
		)
	);
	std::cout << '\n';

	// Decrypt the message
	RSAES_OAEP_SHA256_Decryptor decryptor(privKey);
	std::string symKey;
	StringSource(
		symKeyMessage, true,
		new PK_DecryptorFilter(
			rng, decryptor,
			new StringSink(symKey)
		)
	);

	// Print the received symmetric key
	std::string symKeyStr;
	StringSource(
		symKey, true,
		new HexEncoder(
			new StringSink(symKeyStr)
		)
	);
	std::cout << "Received symmetric key: " << symKeyStr << '\n';

	std::string aesKeyEncrypted;
	RSAES_OAEP_SHA256_Encryptor encryptor(pubKeyAlice);
	StringSource(
		symKey, true,
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
