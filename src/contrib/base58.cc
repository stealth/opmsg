/* Slightly based on bitcoins base58.cpp
 */
#include <stdint.h>
#include <string.h>
#include <vector>
#include <string>


static const char* b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

using namespace std;

string b58_decode(const string &from, string &to)
{
	to = "";

	unsigned int zeroes = 0, i = 0;
	for (;from[i] == '1' && i < from.size(); ++i)
		++zeroes;

	std::vector<unsigned char> b256((from.size() - i) * 733 / 1000 + 1); // log(58) / log(256), rounded up.

	char c;
	const char *ch = nullptr;
	while (i < from.size()) {
		c = from[i];
		if (!(ch = strchr(b58, c)))
			return to;

		// Apply "b256 = b256 * 58 + ch".
		unsigned int carry = ch - b58;
		for (auto it = b256.rbegin(); it != b256.rend(); ++it) {
			carry += 58 * (*it);
			*it = carry % 256;
			carry /= 256;
		}
		++i;
	}

	// Skip leading zeroes in b256.
	auto it = b256.begin();
	while (it != b256.end() && *it == 0)
        	++it;

	to.resize(zeroes + (b256.end() - it));
	to = string(zeroes, 0);
	to.append(it, b256.end());

	return to;
}



string b58_encode(const string &from, string &to)
{
	to = "";

	unsigned int zeroes = 0, length = 0, i = 0;

	for (; from[i] == 0 && i < from.size(); ++i)
		++zeroes;

	unsigned int size = (from.size() - i) * 138 / 100 + 1; // log(256) / log(58), rounded up.
	std::vector<unsigned char> enc(size);

	unsigned char c;
	while (i < from.size()) {
		c = (unsigned char)(from[i]);
		unsigned int carry = c, j = 0;

		// Apply "b58 = b58 * 256 + ch".
		for (auto it = enc.rbegin(); (carry != 0 || j < length) && (it != enc.rend()); it++, j++) {
			carry += 256 * (*it);
			*it = carry % 58;
			carry /= 58;
		}

		length = j;
		++i;
	}

	// Skip leading zeroes in base58 result.
	auto it = enc.begin() + (size - length);
	while (it != enc.end() && *it == 0)
        	++it;

	to.reserve(zeroes + (enc.end() - it));
	to.assign(zeroes, '1');
	while (it != enc.end())
        	to += b58[*it++];

	return to;
}


