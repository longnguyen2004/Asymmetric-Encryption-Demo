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

void main_bob()
{
	AutoSeededRandomPool rng;

	std::cout << "------------ Bob ------------\n";
	// Generate public-private key pair
	std::cout << "Generating public-private key pair\n";
	auto [privKey, pubKey] = generateRSAKeyPair();
	{
		std::string pubKeyHex;
		HexEncoder pubKeyEncoder(
			new StringSink(pubKeyHex)
		);
		pubKey.Save(pubKeyEncoder);
		std::cout << "Public key: " << pubKeyHex << '\n';
		std::cout << "Send this to Alice!\n";
		std::cout << '\n';
	}
	
	// Get Alice's public key
	RSA::PublicKey pubKeyAlice;
	{
		std::string pubKeyAliceHex;
		std::cout << "Alice's public key: ";
		std::getline(std::cin >> std::ws, pubKeyAliceHex);
		std::cout << '\n';
		StringSource pubKeySource(
			pubKeyAliceHex, true,
			new HexDecoder()
		);
		pubKeyAlice.Load(pubKeySource);
	}

	// Get Alice's nonce and decrypt
	CryptoPP::word32 nonceAlice;
	{
		std::string nonceAliceMessage;
		std::cout << "Alice's nonce message: ";
		std::getline(std::cin >> std::ws, nonceAliceMessage);
		RSAES_OAEP_SHA256_Decryptor decryptor(privKey);
		StringSource decrypted(
			nonceAliceMessage, true,
			new HexDecoder(
				new PK_DecryptorFilter(
					rng, decryptor
				)
			)
		);
		decrypted.GetWord32(nonceAlice);
	}
	std::cout << "Alice's nonce: " << nonceAlice << '\n';
	std::cout << '\n';

	// Generate Bob's nonce, then encrypt Alice's nonce + Bob's nonce
	CryptoPP::word32 nonceBob = rng.GenerateWord32();
	{
		std::string nonceAliceBobMessage;
		std::cout << "Bob's nonce: " << nonceBob << '\n';
		RSAES_OAEP_SHA256_Encryptor encryptor(pubKeyAlice);
		PK_EncryptorFilter encryptorFilter(
			rng, encryptor,
			new HexEncoder(
				new StringSink(nonceAliceBobMessage)
			)
		);
		encryptorFilter.PutWord32(nonceAlice);
		encryptorFilter.PutWord32(nonceBob);
		encryptorFilter.MessageEnd();
		std::cout << "Encrypted Alice + Bob's nonce: " << nonceAliceBobMessage << '\n';
		std::cout << "Send this to Alice!\n";
	}

	// Get Alice's nonce ACK
	{
		CryptoPP::word32 nonceAck;
		std::string nonceBobAckMessage;
		std::cout << "Alice's nonce ACK message: ";
		std::getline(std::cin >> std::ws, nonceBobAckMessage);
		std::cout << '\n';

		RSAES_OAEP_SHA256_Decryptor decryptor(privKey);
		StringSource decrypted(
			nonceBobAckMessage, true,
			new HexDecoder(
				new PK_DecryptorFilter(
					rng, decryptor
				)
			)
		);
		decrypted.GetWord32(nonceAck);
		if (nonceBob != nonceAck)
		{
			std::cout << "Mismatched nonce!\n";
			return;
		}
	}
	
	// Get Alice's generated symmetric key
	SecByteBlock aesKey(32);
	{
		// Decrypt the key
		std::string aesKeyMessage;
		std::cout << "Alice's symmetric key message: ";
		std::getline(std::cin >> std::ws, aesKeyMessage);
		{
			RSAES_OAEP_SHA256_Decryptor decryptor(privKey);
			StringSource decrypted(
				aesKeyMessage, true,
				new HexDecoder(
					new PK_DecryptorFilter(
						rng, decryptor,
						new ArraySink(
							aesKey.data(), aesKey.size()
						)
					)
				)
			);
		}
	}
	{
		// Decrypt the signature
		std::string aesKeySignatureMessage;
		std::cout << "Alice's signature message: ";
		std::getline(std::cin >> std::ws, aesKeySignatureMessage);
		{
			StringSource decrypted(
				aesKeySignatureMessage, true,
				new HexDecoder()
			);
			Integer sigEncrypted(decrypted, privKey.MaxPreimage().ByteCount());
			Integer sigInteger = privKey.CalculateInverse(rng, sigEncrypted);
			std::string signature(sigInteger.MinEncodedSize(), '\0');
			sigInteger.Encode((CryptoPP::byte*)signature.data(), signature.size());

			RSASSA_PKCS1v15_SHA256_Verifier verifier(pubKeyAlice);
			if (!verifier.VerifyMessage(aesKey.data(), aesKey.size(), (CryptoPP::byte*)signature.data(), signature.size()))
			{
				std::cout << "Signature check failed!";
				return;
			}
		}
	}
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
}