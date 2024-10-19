#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <fstream>
#include <iostream>
#include <vector>
#include <getopt.h>

/**
* Функция-обработчик ошибок
*/
void handleErrors() {
	ERR_print_errors_fp(stderr);
	abort();
}

/**
* Считывает файл
* @param filename имя файла, который требуется подписать или проверить подпись к нему
* @return вектор байтов с содержимым файла
*/
std::vector<unsigned char> readFile(const std::string& filename) {
	std::ifstream file(filename, std::ios::binary);
	if (!file.is_open())
		throw std::runtime_error("Could not open file: " + filename);

	std::vector<unsigned char> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
	return data;
}

/**
* Генерация подписи
* @param data вектор байтов, представляющий данные, которые нужно подписать (содержимое файла)
* @param privateKey указатель на структуру EVP_PKEY, содержащую секретный ключ, который будет использован для создания подписи
* @return вектор байтов, содержащий цифровую подпись, которая была создана на основе данных и секретного ключа
*/
std::vector<unsigned char> signFile(const std::vector<unsigned char>& data, EVP_PKEY* privateKey) {
	EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
	if (!mdctx) handleErrors();

	if (1 != EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, privateKey))
		handleErrors();

	if (1 != EVP_DigestSignUpdate(mdctx, data.data(), data.size()))
		handleErrors();

	size_t siglen;
	if (1 != EVP_DigestSignFinal(mdctx, nullptr, &siglen))
		handleErrors();

	std::vector<unsigned char> signature(siglen);
	if (1 != EVP_DigestSignFinal(mdctx, signature.data(), &siglen))
		handleErrors();

	signature.resize(siglen);
	EVP_MD_CTX_free(mdctx);
	return signature;
}

/**
* Проверка подписи
* @param data байтовый вектор, представляющий данные, которые будут подписаны
* @param signature вектор байтов, содержащий подпись, которая была ранее создана с использованием секретного ключа
* @param publicKey указатель на структуру EVP_PKEY, содержащую открытый ключ
* @return 1, если подпись действительна; 0 - иначе
*/
bool verifySignature(const std::vector<unsigned char>& data, const std::vector<unsigned char>& signature, EVP_PKEY* publicKey) {
	EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
	if (!mdctx) handleErrors();

	if (1 != EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr, publicKey))
		handleErrors();

	if (1 != EVP_DigestVerifyUpdate(mdctx, data.data(), data.size()))
		handleErrors();

	int ret = EVP_DigestVerifyFinal(mdctx, signature.data(), signature.size());
	EVP_MD_CTX_free(mdctx);

	return ret == 1;
}

/**
* В программе поддерживается три опции:
* -m - режим работы (sign - подписать файл, verify - проверить подпись)
* -f - путь до подписываемого файла
* -k - путь до ключа подписи (при генерации подписи - путь до секретного, при проверке подписи - путь до открытого)
*/
int main(int argc, char** argv) {
	std::string mode;
	std::string filename;
	std::string keyfile;

	int opt;
	while ((opt = getopt(argc, argv, "m:f:k:")) != -1) {
		switch (opt) {
		case 'm':
			mode = optarg;
			break;
		case 'f':
			filename = optarg;
			break;
		case 'k':
			keyfile = optarg;
			break;
		default:
			std::cerr << "Usage: " << argv[0] << " -m <sign/verify> -f <file> -k <key.pem>" << std::endl;
			return 1;
		}
	}

	if (mode.empty() || filename.empty() || keyfile.empty()) {
		std::cerr << "All options -m, -f, and -k are required." << std::endl;
		return 1;
	}

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	try {
		std::vector<unsigned char> data = readFile(filename);

		FILE* key_fp = fopen(keyfile.c_str(), "r");
		if (!key_fp)
			throw std::runtime_error("Could not open key file: " + keyfile);

		if (mode == "sign") {
			EVP_PKEY* privateKey = PEM_read_PrivateKey(key_fp, nullptr, nullptr, nullptr);
			if (!privateKey)
				handleErrors();

			std::vector<unsigned char> signature = signFile(data, privateKey);
			EVP_PKEY_free(privateKey);

			std::ofstream sigfile(filename + ".sig", std::ios::binary);
			sigfile.write(reinterpret_cast<const char*>(signature.data()), signature.size());

			std::cout << "File signed successfully." << std::endl;
		}
		else if (mode == "verify") {
			EVP_PKEY* publicKey = PEM_read_PUBKEY(key_fp, nullptr, nullptr, nullptr);
			if (!publicKey)
				handleErrors();

			std::vector<unsigned char> signature = readFile(filename + ".sig");

			if (verifySignature(data, signature, publicKey))
				std::cout << "Signature is valid." << std::endl;
			else
				std::cout << "Signature is invalid." << std::endl;

			EVP_PKEY_free(publicKey);
		}
		else
			std::cerr << "Invalid mode: " << mode << std::endl;

		fclose(key_fp);
	}
	catch (const std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
	EVP_cleanup();
	ERR_free_strings();
	return 0;
}
