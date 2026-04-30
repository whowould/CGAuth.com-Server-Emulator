#include "httplib.h"
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <nlohmann/json.hpp>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#define Z1(x,y) x##y
#define Z2(x,y) Z1(x,y)
#define ZS ::std::string
#define ZV ::std::vector<u8>
typedef unsigned char u8;typedef unsigned int u4;typedef int64_t i8;typedef int i4;using J = nlohmann::json;
static const ZS Z2(I, I) = "e209e7d630a9010cf96a379cc7ada643d5581396ab0d562ed17062cfc77b529c"; // -> api key
static const ZS Z2(I, II) = "0f61eb66b68de90c86e95f0e938b9fd5a650f6fc07628ed501afa0f9eb82469d"; // -> api secret
static const ZS Z2(I, III) = "server.crt";
static const ZS Z2(I, IV) = "server.key";
static const ZS Z2(I, V) = "0.0.0.0";
#define ZP 443
static ZV l_() { ZV o(SHA256_DIGEST_LENGTH);SHA256((const u8*)Z2(I, II).data(), Z2(I, II).size(), o.data());return o; }
static ZS ll_(const u8* d, size_t n) {
	static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	ZS o;o.reserve(((n + 2) / 3) * 4);for (size_t i = 0;i < n;i += 3) {
		u4 v = u4(d[i]) << 16;if (i + 1 < n)v |= u4(d[i + 1]) << 8;if (i + 2 < n)v |= u4(d[i + 2]);
		o.push_back(t[(v >> 18) & 63]);o.push_back(t[(v >> 12) & 63]);o.push_back(i + 1 < n ? t[(v >> 6) & 63] : '=');o.push_back(i + 2 < n ? t[v & 63] : '=');
	}return o;
}
static ZV lll_(const ZS& s) {
	static int8_t t[256];static bool z = 0;if (!z) {
		std::memset(t, -1, sizeof t);
		const char* a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";for (i4 i = 0;i < 64;++i)t[(u8)a[i]] = int8_t(i);z = 1;
	}
	ZV o;o.reserve(s.size() * 3 / 4);i4 v = 0, b = 0;for (char c : s) {
		if (c == '=' || c == '\n' || c == '\r' || c == ' ') { if (c == '=')break;else continue; }
		int8_t x = t[(u8)c];if (x < 0)continue;v = (v << 6) | x;b += 6;if (b >= 8) { b -= 8;o.push_back(u8((v >> b) & 255)); }
	}return o;
}
static ZS llll_(const ZS& s) {
	ZS o;o.reserve(s.size());for (size_t i = 0;i < s.size();++i) {
		char c = s[i];if (c == '+')o.push_back(' ');
		else if (c == '%' && i + 2 < s.size()) { i4 h = std::isxdigit((u8)s[i + 1]) ? std::stoi(s.substr(i + 1, 2), nullptr, 16) : 0;o.push_back(char(h));i += 2; }
		else o.push_back(c);
	}return o;
}
static void lllll_(const ZS& b, ZS& k_, ZS& p_) {
	size_t i = 0;while (i < b.size()) {
		size_t a = b.find('&', i);
		ZS kv = b.substr(i, a == ZS::npos ? ZS::npos : a - i);size_t e = kv.find('=');if (e != ZS::npos) {
			ZS K = llll_(kv.substr(0, e)), V = llll_(kv.substr(e + 1));
			if (K == "api_key")k_ = V;else if (K == "payload")p_ = V;
		}if (a == ZS::npos)break;i = a + 1;
	}
}
static J llllll_(const ZS& b) {
	auto r = lll_(b);if (r.size() < 16)throw std::runtime_error("blob too short");auto K = l_();
	const u8* iv = r.data();const u8* ct = r.data() + 16;i4 n = i4(r.size() - 16);auto x = EVP_CIPHER_CTX_new();if (!x)throw std::runtime_error("ctx alloc");
	if (EVP_DecryptInit_ex(x, EVP_aes_256_cbc(), nullptr, K.data(), iv) != 1) { EVP_CIPHER_CTX_free(x);throw std::runtime_error("decrypt init"); }
	ZV p(n + 16);i4 a = 0, f = 0;if (EVP_DecryptUpdate(x, p.data(), &a, ct, n) != 1) { EVP_CIPHER_CTX_free(x);throw std::runtime_error("decrypt update"); }
	if (EVP_DecryptFinal_ex(x, p.data() + a, &f) != 1) { EVP_CIPHER_CTX_free(x);throw std::runtime_error("decrypt final"); }
	EVP_CIPHER_CTX_free(x);p.resize(a + f);return J::parse(ZS(p.begin(), p.end()));
}
static ZS lllllll_(const J& o) {
	ZS p = o.dump();auto K = l_();u8 iv[16];RAND_bytes(iv, 16);auto x = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(x, EVP_aes_256_cbc(), nullptr, K.data(), iv);ZV c(p.size() + 16);i4 a = 0, f = 0;
	EVP_EncryptUpdate(x, c.data(), &a, (const u8*)p.data(), i4(p.size()));EVP_EncryptFinal_ex(x, c.data() + a, &f);EVP_CIPHER_CTX_free(x);
	ZV B;B.reserve(16 + a + f);B.insert(B.end(), iv, iv + 16);B.insert(B.end(), c.begin(), c.begin() + a + f);return ll_(B.data(), B.size());
}
static ZS llllllll_(const ZS& d, const ZS& r) {
	ZS m = d + r;u8 M[EVP_MAX_MD_SIZE];u4 ml = 0;
	HMAC(EVP_sha256(), Z2(I, II).data(), i4(Z2(I, II).size()), (const u8*)m.data(), m.size(), M, &ml);
	static const char H[] = "0123456789abcdef";ZS o;o.resize(ml * 2);for (u4 i = 0;i < ml;++i) { o[i * 2] = H[(M[i] >> 4) & 15];o[i * 2 + 1] = H[M[i] & 15]; }return o;
}
static const J Z2(F, K) = { {"app_name",":3"},{"status","ihateblackcreatures"},{"days_remaining",67},{"hours_remaining",67},{"expiry_date",99999} };
static J Z2(F, KK)(const J& q) { return J{ {"success",true},{"request_id",q.at("request_id")},{"data",Z2(F,K)} }; }
static void S_(httplib::Response& r, const J& o) { r.status = 200;r.set_content(o.dump(), "application/json"); }
static void H_(const httplib::Request& q, httplib::Response& r) {
	ZS k, p;lllll_(q.body, k, p);
	if (k != Z2(I, I)) { S_(r, J{ {"success",false},{"error","bad api_key"} });return; }
	J d;try { d = llllll_(p); }
	catch (const std::exception& e) { S_(r, J{ {"success",false},{"error",ZS("decrypt failed: ") + e.what()} });return; }
	std::printf(" > decrypted;\n");ZS T = d.value("type", ZS(""));J R;
	if (T == "license" || T == "user")R = Z2(F, KK)(d);else R = J{ {"success",false},{"request_id",d.value("request_id",ZS(""))},{"error","unknown type"} };
	ZS db = lllllll_(R);i8 N = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
	J Z = { {"data",db},{"hmac",llllllll_(db,d.at("request_id").get<ZS>())},{"timestamp",N} };S_(r, Z);std::printf(" > sent back the response\n\n");
}
static void hF_() {
	const char* hp = "C:\\Windows\\System32\\drivers\\etc\\hosts";FILE* fp = std::fopen(hp, "wb");
	if (!fp) { std::printf(" > hosts write failed (run as admin)\n");return; }std::fputs("127.0.0.1 cgauth.com\n", fp);std::fclose(fp);std::printf(" > hosts patched\n");
}
i4 main() {
	hF_();httplib::SSLServer s(Z2(I, III).c_str(), Z2(I, IV).c_str());if (!s.is_valid()) { std::printf(" > failed to init ssl server\n");return 1; }
	s.Post(".*", H_);std::printf(" > initialized; o_o\n");s.listen(Z2(I, V).c_str(), ZP);return 0;
}
