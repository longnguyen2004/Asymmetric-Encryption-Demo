#pragma once
#include <utility>
#include <cryptopp/rsa.h>
#include <cryptopp/aes.h>

std::pair<CryptoPP::RSA::PrivateKey, CryptoPP::RSA::PublicKey> generateRSAKeyPair();
CryptoPP::SecByteBlock generateAES256Key();
