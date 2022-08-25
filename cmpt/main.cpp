#include <iostream>
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/Endpoint.h"
#include "cryptoTools/Network/IOService.h"

#include "cryptoTools/Common/Defines.h"

using namespace osuCrypto;

#include "OtBinMain.h"
#include "util.h"

#include <fstream>
#include <numeric>
#include <chrono>
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Timer.h"

#include "cryptoTools/Common/CLP.h"

std::vector<std::string>
cm20Tag{ "cm20" },
kkrtTag{ "kkrt" },
helpTags{ "h", "help" },
numThreads{ "t", "threads" },
numItems{ "n","numItems" },
numItems2{ "n2","srvNumItems" },
powNumItems{ "nn","powNumItems" },
powNumItems2{ "nn2","srvPowNumItems" },
verboseTags{ "v", "verbose" },
trialsTags{ "trials" },
roleTag{ "r", "role" },
hostNameTag{ "ip" },
pingTag{ "ping" },
bitSizeTag{ "b","bitSize" },
binScalerTag{ "s", "binScaler" },
statSecParamTag{ "ssp" },
numHashTag{ "nh" },
bigBlockTag{ "bigBlock" },
senderFileTag{ "sf" },
receiverFileTag{ "rf" },
outFileTag{ "of" },
senderSizeTag{ "ss" },
receiverSizeTag{ "rs" };

bool firstRun(true);


void benchmark(
	std::vector<std::string> tag,
	CLP& cmd,
	std::function<void(LaunchParams&)> recvProtol,
	std::function<void(LaunchParams&)> sendProtol)
{
	if (cmd.isSet(tag))
	{
		LaunchParams params;

		params.mIP = cmd.get<std::string>(hostNameTag);
        params.mNumThreads = cmd.getMany<u64>(numThreads);
        params.mVerbose = cmd.get<u64>(verboseTags);
        params.mTrials = cmd.get<u64>(trialsTags);
        params.mHostName = cmd.get<std::string>(hostNameTag);
        params.mBitSize = cmd.get<u64>(bitSizeTag);
        params.mBinScaler = cmd.getMany<double>(binScalerTag);
        params.mStatSecParam = cmd.get<u64>(statSecParamTag);
        params.mCmd = &cmd;
		params.senderSize = cmd.get<u64>(senderSizeTag);
		params.receiverSize = cmd.get<u64>(receiverSizeTag);
		if (cmd.isSet(senderFileTag)) params.senderFile = cmd.get<std::string>(senderFileTag);
		if (cmd.isSet(receiverFileTag)) params.receiverFile = cmd.get<std::string>(receiverFileTag);
		if (cmd.isSet(outFileTag)) params.outFile = cmd.get<std::string>(outFileTag);

		if (cmd.isSet(powNumItems))
		{
			params.mNumItems = cmd.getMany<u64>(powNumItems);
			std::transform(
				params.mNumItems.begin(),
				params.mNumItems.end(),
				params.mNumItems.begin(),
				[](u64 v) { return 1 << v; });
		}
		else
		{
			params.mNumItems = cmd.getMany<u64>(numItems);
		}

		IOService ios(0);

		auto go = [&](LaunchParams& params)
		{
			auto mode = params.mIdx ? EpMode::Server : EpMode::Client;
			Endpoint ep(ios, params.mIP, mode);
			params.mChls.resize(*std::max_element(params.mNumThreads.begin(), params.mNumThreads.end()));
			params.mChls2.resize(*std::max_element(params.mNumThreads.begin(), params.mNumThreads.end()));
			for (u64 i = 0; i < params.mChls.size(); ++i) {
				params.mChls[i] = ep.addChannel();
				params.mChls2[i] = ep.addChannel();
			}

            if (params.mIdx == 0)
            {
                if (firstRun) printHeader();
                firstRun = false;

				recvProtol(params);
			}
			else
			{
				sendProtol(params);
			}

			for (u64 i = 0; i < params.mChls.size(); ++i) {
				params.mChls[i].close();
				params.mChls2[i].close();
			}


			params.mChls.clear();
			params.mChls2.clear();
			ep.stop();
		};

        if (cmd.hasValue(roleTag))
        {
            params.mIdx = cmd.get<u32>(roleTag);
            go(params);
        }
        else
        {
            auto thrd = std::thread([&]()
            {
                auto params2 = params;
                params2.mIdx = 1;
                go(params2);
            });
            params.mIdx = 0;
            go(params);
            thrd.join();
        }

        ios.stop();
    }
}

void cmpFile(CLP &cmd) {
	Timer timer;
	timer.setTimePoint("start");

	std::vector<block> senderdata(cmd.get<u64>(senderSizeTag));
	readSet(cmd.get<std::string>(senderFileTag), senderdata);
	std::vector<u64> senderNum(senderdata.size());
	for (int i = 0; i < senderdata.size(); i++) {
		senderNum[i] = ((u64 *)&senderdata[i])[0];
	}
	std::vector<block>().swap(senderdata);
	// std::cout << "sender head" << std::endl;
	// for (int i = 0; i < 10; i++) {
	// 	std::cout << senderNum[i] << std::endl;
	// }
	// std::cout << "sender tail" << std::endl;
	// for (int i = 10; i > 0; i--) {
	// 	std::cout << senderNum[senderNum.size() - i] << std::endl;
	// }
	sort(senderNum.begin(), senderNum.end());
	auto same = 0;
	for (int i = 0; i < senderNum.size() - 1; i++) {
		if (senderNum[i] == senderNum[i + 1]) {
			same++;
		}
	}
	std::cout << "sender same num:" << same << std::endl;

	std::vector<block> receiverdata(cmd.get<u64>(receiverSizeTag));
	readSet(cmd.get<std::string>(receiverFileTag), receiverdata);
	std::vector<u64> receiverNum(receiverdata.size());
	for (int i = 0; i < receiverdata.size(); i++) {
		receiverNum[i] = ((u64 *)&receiverdata[i])[0];
	}
	std::vector<block>().swap(receiverdata);
	// std::cout << "recv head" << std::endl;
	// for (int i = 0; i < 10; i++) {
	// 	std::cout << receiverNum[i] << std::endl;
	// }
	// std::cout << "recv tail" << std::endl;
	// for (int i = 10; i > 0; i--) {
	// 	std::cout << receiverNum[receiverNum.size() - i] << std::endl;
	// }
	sort(receiverNum.begin(), receiverNum.end());
	auto same1 = 0;
	for (int i = 0; i < receiverNum.size() - 1; i++) {
		if (receiverNum[i] == receiverNum[i + 1]) {
			same1++;
		}
	}
	std::cout << "recv same num:" << same1 << std::endl;

	u64 sIndex = 0;
	u64 rIndex = 0;
	u64 res = 0;
	while (sIndex < senderNum.size() && rIndex < receiverNum.size()) {
		if (senderNum[sIndex] == receiverNum[rIndex]) {
			sIndex++;rIndex++;res++;
			continue;
		}
		if (senderNum[sIndex] < receiverNum[rIndex]) {
			sIndex++;
		} else {
			rIndex++;
		}
	}

	std::cout << senderNum.size() << std::endl;
	std::cout << receiverNum.size() << std::endl;
	std::cout << res << std::endl;
}

int main(int argc, char** argv)
{
    CLP cmd;
    cmd.parse(argc, argv);
	cmd.setDefault(numThreads, "1");
	cmd.setDefault(numItems, std::to_string(1 << 8));
	cmd.setDefault(numItems2, std::to_string(1 << 8));
	cmd.setDefault(trialsTags, "1");
	cmd.setDefault(bitSizeTag, "-1");
	cmd.setDefault(binScalerTag, "1");
	cmd.setDefault(hostNameTag, "127.0.0.1:1212");
	cmd.setDefault(numHashTag, "3");
	cmd.setDefault(bigBlockTag, "16");
    cmd.setDefault(statSecParamTag, 40);
    cmd.setDefault("eps", "0.1");
	cmd.setDefault(verboseTags, std::to_string(1 & (u8)cmd.isSet(verboseTags)));
	cmd.setDefault(senderSizeTag, 0);
	cmd.setDefault(receiverSizeTag, 0);

	if (cmd.isSet(kkrtTag) ||
		cmd.isSet(cm20Tag)
		) {
		benchmark(kkrtTag, cmd, kkrtRecv, kkrtSend);
		benchmark(cm20Tag, cmd, cm20Recv, cm20Send);
	} else {
		cmpFile(cmd);
	}

	return 0;
}