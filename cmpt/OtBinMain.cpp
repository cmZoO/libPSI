#include "cryptoTools/Network/Endpoint.h" 

#include "libPSI/MPSI/Rr17/Rr17a/Rr17aMPsiReceiver.h"
#include "libPSI/MPSI/Rr17/Rr17a/Rr17aMPsiSender.h"
#include "libPSI/MPSI/Rr17/Rr17b/Rr17bMPsiReceiver.h"
#include "libPSI/MPSI/Rr17/Rr17b/Rr17bMPsiSender.h"


#include "libPSI/MPSI/Grr18/Grr18MPsiReceiver.h"
#include "libPSI/MPSI/Grr18/Grr18MPsiSender.h"

#include "libPSI/PSI/Kkrt/KkrtPsiReceiver.h"
#include "libPSI/PSI/Kkrt/KkrtPsiSender.h"

#include <fstream>
using namespace osuCrypto;
#include "util.h"

#include "cryptoTools/Common/Defines.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"

#include "libPSI/PSI/Cm20/Cm20PsiReceiver.h"
#include "libPSI/PSI/Cm20/Cm20PsiSender.h"

#include "libOTe/NChooseOne/Oos/OosNcoOtReceiver.h"
#include "libOTe/NChooseOne/Oos/OosNcoOtSender.h"
#include "libOTe/NChooseOne/RR17/Rr17NcoOtReceiver.h"
#include "libOTe/NChooseOne/RR17/Rr17NcoOtSender.h"

#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <numeric>
u8 dummy[1];


void readSet(const std::string& path, std::vector<block> &data)
{
    std::cout << "read data frome file:" << path << std::endl;
	std::ifstream file(path, std::ios::in);
	if (file.is_open() == false)
		throw std::runtime_error("failed to open file: " + path);
	std::string buffer;
    char *ptr;
    std::getline(file, buffer);
    u64 index = 0;
	while (std::getline(file, buffer) && index < data.size())
	{
		((u64 *)&data[index++])[0] = std::strtoul(buffer.c_str(), &ptr, 10);
	}
    std::cout << data.size() << " lines of data have read" << std::endl;
}

void writeOutput(std::string outPath, const std::vector<u64>& intersection, std::vector<block> &data)
{
	std::ofstream file;
	file.open(outPath, std::ios::out | std::ios::trunc);
	if (file.is_open() == false)
		throw std::runtime_error("failed to open the output file: " + outPath);
    file << "id" << "\n";
	for (auto i : intersection)
		file << ((u64 *)&data[i])[0] << "\n";
}

void kkrtSend(
    LaunchParams& params)
{
    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));

    for (auto setSize : params.mNumItems)
    {
        for (auto cc : params.mNumThreads)
        {
            std::vector<Channel> sendChls = params.getChannels(cc);
            std::vector<Channel> maskChls = params.getChannels2(cc);

            u64 senderSize, receiverSize;
            senderSize = receiverSize = setSize;
            if (params.senderSize && params.receiverSize) {
                senderSize = params.senderSize;
                receiverSize = params.receiverSize;
            }

            for (u64 jj = 0; jj < params.mTrials; jj++)
            {
                
                std::vector<block> sendSet(senderSize);
                if (params.senderFile.size()) {
                    readSet(params.senderFile, sendSet);
                } else {
                    for (u64 i = 0; i < senderSize; ++i)
                    {
                        sendSet[i] = prng.get<block>();
                        if (i < senderSize / 2) {
                            memset(&sendSet[i], 0, sizeof(block));
                            ((u64 *)&sendSet[i])[0] = i;
                        } 
                    }
                }

                KkrtPsiSender sendPSIs;
                sendPSIs.setTimer(gTimer);

                sendChls[0].asyncSend(dummy, 1);
                sendChls[0].recv(dummy, 1);

                sendPSIs.init(senderSize, receiverSize, params.mStatSecParam, sendChls, prng.get<block>());

                sendPSIs.sendInput(sendSet, sendChls, maskChls);

                for (u64 g = 0; g < sendChls.size(); ++g) {
                    sendChls[g].resetStats();
                    maskChls[g].resetStats();
                }
            }
        }
    }
}

void kkrtRecv(
    LaunchParams& params)
{
    setThreadName("CP_Test_Thread");

    PRNG prng(_mm_set_epi32(4253465, 746587658, 234435, 23987045));

    if (params.mVerbose) std::cout << "\n";

    for (auto setSize : params.mNumItems)
    {
        for (auto numThreads : params.mNumThreads)
        {
            auto chls = params.getChannels(numThreads);
            auto mchls = params.getChannels2(numThreads);
            u64 senderSize, receiverSize;
            senderSize = receiverSize = setSize;
            if (params.senderSize && params.receiverSize) {
                senderSize = params.senderSize;
                receiverSize = params.receiverSize;
            }
            std::cout << "senderSize  :" << senderSize << std::endl;
            std::cout << "receiverSize:" << receiverSize << std::endl;

            for (u64 jj = 0; jj < params.mTrials; jj++)
            {
                std::string tag("kkrt");
                std::vector<block> recvSet(receiverSize);
                if (params.receiverFile.size()) {
                    readSet(params.receiverFile, recvSet);
                } else {
                    for (u64 i = 0; i < receiverSize; ++i)
                    {
                        recvSet[i] = prng.get<block>();
                        if (i < receiverSize / 2) {
                            memset(&recvSet[i], 0, sizeof(block));
                            ((u64 *)&recvSet[i])[0] = i;
                        } 
                    }
                }

                KkrtPsiReceiver recvPSIs;
                recvPSIs.setTimer(gTimer);

                chls[0].recv(dummy, 1);
                gTimer.reset();
                chls[0].asyncSend(dummy, 1);

                Timer timer;

                auto start = timer.setTimePoint("start");

                recvPSIs.init(senderSize, receiverSize, params.mStatSecParam, chls, prng.get<block>());

                auto mid = timer.setTimePoint("init");

                recvPSIs.sendInput(recvSet, chls, mchls);

                auto end = timer.setTimePoint("done");

                auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
                auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();

                printTimings(tag, chls, offlineTime, onlineTime, params, receiverSize, numThreads, 1, &mchls);

                if (params.outFile.size()) {
                    std::cout << "intersection size " << recvPSIs.mIntersection.size() << std::endl;
                    writeOutput(params.outFile, recvPSIs.mIntersection, recvSet);
                } else {
                    if (recvPSIs.mIntersection.size() != receiverSize / 2) {
                        std::cout << "intersection size " << recvPSIs.mIntersection.size() << " not match" << receiverSize / 2 << std::endl;
                    }
                    sort(recvPSIs.mIntersection.begin(), recvPSIs.mIntersection.end());
                    int i;
                    for (i = 0; i < recvPSIs.mIntersection.size(); i++) {
                        if (recvPSIs.mIntersection[i] != i) {
                            break;
                        }
                    }
                    if (i != recvPSIs.mIntersection.size()) {
                        std::cout << "intersection wrong result" << std::endl;
                    } 
                }
            }
        }
    }
}

void cm20Send(
    LaunchParams& params)
{
    setThreadName("CP_Test_Thread");

    PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987045));


    for (auto setSize : params.mNumItems)
    {
        for (auto cc : params.mNumThreads)
        {
            std::vector<Channel> sendChls = params.getChannels(cc);
            u64 senderSize, receiverSize;
            senderSize = receiverSize = setSize;
            if (params.senderSize && params.receiverSize) {
                senderSize = params.senderSize;
                receiverSize = params.receiverSize;
            }
            double scale = params.mBinScaler.size() == 0 ? 2 : params.mBinScaler[0];

            for (u64 jj = 0; jj < params.mTrials; jj++)
            {
                
                std::vector<block> sendSet(senderSize);
                if (params.senderFile.size()) {
                    readSet(params.senderFile, sendSet);
                } else {
                    for (u64 i = 0; i < senderSize; ++i)
                    {
                        sendSet[i] = prng.get<block>();
                        if (i < senderSize / 2) {
                            memset(&sendSet[i], 0, sizeof(block));
                            ((u64 *)&sendSet[i])[0] = i;
                        } 
                    }
                }

                Cm20PsiSender sendPSIs;
                Timer timer;
                sendPSIs.setTimer(timer);
                auto start = timer.setTimePoint("start");

                sendChls[0].asyncSend(dummy, 1);
                sendChls[0].recv(dummy, 1);

                sendPSIs.init(senderSize, receiverSize, scale, cc, params.mStatSecParam, sendChls, prng.get<block>());

                //sendChls[0].asyncSend(dummy, 1);
                //sendChls[0].recv(dummy, 1);

                sendPSIs.sendInput(sendSet, sendChls);

                // std::cout << sendPSIs.getTimer();

                for (u64 g = 0; g < sendChls.size(); ++g)
                    sendChls[g].resetStats();
            }
        }
    }
}

void cm20Recv(
    LaunchParams& params)
{
    setThreadName("CP_Test_Thread");

    //LinearCode code;
    //code.loadBinFile(SOLUTION_DIR "/../libOTe/libOTe/Tools/bch511.bin");


    PRNG prng(_mm_set_epi32(4253465, 746587658, 234435, 23987045));


    if (params.mVerbose) std::cout << "\n";

    for (auto setSize : params.mNumItems)
    {
        for (auto numThreads : params.mNumThreads)
        {
            auto chls = params.getChannels(numThreads);
            u64 senderSize, receiverSize;
            senderSize = receiverSize = setSize;
            if (params.senderSize && params.receiverSize) {
                senderSize = params.senderSize;
                receiverSize = params.receiverSize;
            }
            double scale = params.mBinScaler[0];
            std::cout << "senderSize  :" << senderSize << std::endl;
            std::cout << "receiverSize:" << receiverSize << std::endl;
            std::cout << "scale       :" << scale << std::endl;

            for (u64 jj = 0; jj < params.mTrials; jj++)
            {

                std::string tag("cm20");

                std::vector<block> recvSet(receiverSize);
                if (params.receiverFile.size()) {
                    readSet(params.receiverFile, recvSet);
                } else {
                    for (u64 i = 0; i < receiverSize; ++i)
                    {
                        recvSet[i] = prng.get<block>();
                        if (i < receiverSize / 2) {
                            memset(&recvSet[i], 0, sizeof(block));
                            ((u64 *)&recvSet[i])[0] = i;
                        } 
                    }
                }
                Cm20PsiReceiver recvPSIs;

                chls[0].recv(dummy, 1);
                gTimer.reset();
                chls[0].asyncSend(dummy, 1);

                Timer timer;
                recvPSIs.setTimer(timer);
                auto start = timer.setTimePoint("start");

                recvPSIs.init(senderSize, receiverSize, scale, numThreads, params.mStatSecParam, chls, prng.get<block>());

                //chls[0].asyncSend(dummy, 1);
                //chls[0].recv(dummy, 1);
                auto mid = timer.setTimePoint("inited");


                recvPSIs.sendInput(recvSet, chls);

                auto end = timer.setTimePoint("done");

                auto offlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(mid - start).count();
                auto onlineTime = std::chrono::duration_cast<std::chrono::milliseconds>(end - mid).count();

                //auto byteSent = chls[0]->getTotalDataSent() *chls.size();

                printTimings(tag, chls, offlineTime, onlineTime, params, receiverSize, numThreads);

                // std::cout << timer;

                if (params.outFile.size()) {
                    std::cout << "intersection size " << recvPSIs.mIntersection.size() << std::endl;
                    writeOutput(params.outFile, recvPSIs.mIntersection, recvSet);
                } else {
                    if (recvPSIs.mIntersection.size() != receiverSize / 2) {
                        std::cout << "intersection size " << recvPSIs.mIntersection.size() << " not match" << receiverSize / 2 << std::endl;
                    }
                    sort(recvPSIs.mIntersection.begin(), recvPSIs.mIntersection.end());
                    int i;
                    for (i = 0; i < recvPSIs.mIntersection.size(); i++) {
                        if (recvPSIs.mIntersection[i] != i) {
                            break;
                        }
                    }
                    if (i != recvPSIs.mIntersection.size()) {
                        std::cout << "intersection wrong result" << std::endl;
                    } 
                }
            }
        }
    }
}