#ifndef opmsg_base58_h
#define opmsg_base58_h

#include <string>

std::string b58_encode(const std::string &from, std::string &to);

std::string b58_decode(const std::string &from, std::string &to);

#endif

