#pragma once

#include <vector> 
#include "cryptoTools/Common/Defines.h"
#include "util.h"

void readSet(const std::string& path, std::vector<block> &data);

void writeOutput(std::string outPath, const std::vector<u64>& intersection, std::vector<block> &data);

void kkrtRecv(LaunchParams &params);

void kkrtSend(LaunchParams &params);

void cm20Recv(LaunchParams &params);

void cm20Send(LaunchParams &params);
