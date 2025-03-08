#include "common.h"
#include "main.h"
#include <utility>
#include <iostream>
#include <string>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pssr.h>
#include <cryptopp/sha.h>

using namespace CryptoPP;

void main_alice()
{
	AutoSeededRandomPool rng;

	std::cout << "------------ Alice ------------\n";

	// Generate public-private key pair
	std::cout << "Generating public-private key pair\n";
	auto [privKey, pubKey] = generateRSAKeyPair();
	std::string pubKeyHex;
	{
		HexEncoder pubKeyEncoder(
			new StringSink(pubKeyHex)
		);
		pubKey.Save(pubKeyEncoder);
	}
	std::cout << "Public key: " << pubKeyHex << '\n';
	std::cout << "Send this to Bob!\n";
	std::cout << '\n';

	// Get Bob's public key
	std::string pubKeyBobHex;
	std::cout << "Bob's public key: ";
	std::getline(std::cin >> std::ws, pubKeyBobHex);
	std::cout << '\n';
	RSA::PublicKey pubKeyBob;
	{
		StringSource pubKeySource(
			pubKeyBobHex, true,
			new HexDecoder()
		);
		pubKeyBob.Load(pubKeySource);
	}

	// Encrypt the nonce using Bob's public key
	auto nonce = rng.GenerateWord32();
	std::cout << "Alice's nonce: " << nonce << '\n';

	std::string nonceEncrypted;
	{
		RSAES_OAEP_SHA256_Encryptor encryptor(pubKeyBob);
		PK_EncryptorFilter encryptorFilter(
			rng, encryptor,
			new HexEncoder(
				new StringSink(nonceEncrypted)
			)
		);
		encryptorFilter.PutWord32(nonce);
		encryptorFilter.MessageEnd();
	}
	std::cout << "Encrypted nonce: " << nonceEncrypted << '\n';
	std::cout << "Send this to Bob!\n";
	std::cout << '\n';

	// Receive Alice's nonce + Bob's nonce
	std::string bobNonceMessage;
	std::cout << "Bob's nonce message: ";
	std::getline(std::cin, bobNonceMessage);

	CryptoPP::word32 nonceAck, nonceBob;
	{
		RSAES_OAEP_SHA256_Decryptor decryptor(privKey);
		StringSource decryptedNonce(
			bobNonceMessage, true,
			new HexDecoder(
				new PK_DecryptorFilter(
					rng, decryptor
				)
			)
		);
		decryptedNonce.GetWord32(nonceAck);
		decryptedNonce.GetWord32(nonceBob);
	}
	if (nonce != nonceAck)
	{
		std::cout << "Mismatched nonce!\n";
		return;
	}
	std::cout << "Bob's nonce: " << nonceBob << '\n';
	std::cout << '\n';

	// Resend Bob's nonce
	std::string nonceEncrypted2;
	{
		RSAES_OAEP_SHA256_Encryptor encryptor(pubKeyBob);
		PK_EncryptorFilter encryptorFilter(
			rng, encryptor,
			new HexEncoder(
				new StringSink(nonceEncrypted2)
			)
		);
		encryptorFilter.PutWord32(nonceBob);
		encryptorFilter.MessageEnd();
	}
	std::cout << "Encrypted Bob's nonce: " << nonceEncrypted2 << '\n';
	std::cout << "Send this to Bob!\n";
	std::cout << '\n';

	// Generate a symmetric key and encrypt it with Bob's pub key
	auto aesKey = generateAES256Key();
	{
		std::string aesKeyHex;
		StringSource(
			aesKey.data(), aesKey.size(), true,
			new HexEncoder(
				new StringSink(aesKeyHex)
			)
		);
		std::cout << "Generated symmetric key: " << aesKeyHex << '\n';
	}
	std::string aesKeyMessage;
	std::string aesKeySignatureMessage;
	{
		// Encrypt the key
		RSAES_OAEP_SHA256_Encryptor encryptor(pubKeyBob);
		StringSource(
			aesKey.data(), aesKey.size(), true,
			new PK_EncryptorFilter(
				rng, encryptor,
				new HexEncoder(
					new StringSink(aesKeyMessage)
				)
			)
		);
	}
	{
		// Sign the key
		RSASSA_PKCS1v15_SHA256_Signer signer(privKey);
		StringSource sigSource(
			aesKey.data(), aesKey.size(), true,
			new SignerFilter(rng, signer)
		);
		// Encrypt the signature
		// We use raw RSA here, since the signature is already padded
		Integer sigInteger(sigSource, signer.SignatureLength());
		Integer sigEncrypted = pubKeyBob.ApplyFunction(sigInteger);
		HexEncoder signatureMessageEncoder(
			new StringSink(aesKeySignatureMessage)
		);
		sigEncrypted.Encode(signatureMessageEncoder, pubKeyBob.MaxImage().ByteCount());
	}
	std::cout << "Encrypted symmetric key: " << aesKeyMessage << '\n';
	std::cout << "Encrypted signature: " << aesKeySignatureMessage << '\n';
	std::cout << "Send this to Bob!\n";
}
