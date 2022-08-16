
#include "libPSI/config.h"
#ifdef ENABLE_KKRT_PSI
#include "KkrtPsiReceiver.h"
#include <future>
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Crypto/Commit.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Timer.h"
#include "libPSI/Tools/SimpleHasher.h"
#include <libOTe/Base/BaseOT.h>
#include <unordered_map>
#include "libOTe/TwoChooseOne/IknpOtExtSender.h"
#include <iomanip>
namespace osuCrypto
{


    KkrtPsiReceiver::KkrtPsiReceiver()
    {
    }


    KkrtPsiReceiver::~KkrtPsiReceiver()
    {
    }

    void KkrtPsiReceiver::init(u64 senderSize, u64 recverSize, u64 statSecParam, Channel  chl0, block seed)
    {
        std::array<Channel, 1> chans{ chl0 };
        init(senderSize, recverSize, statSecParam, chans, seed);
    }

    void KkrtPsiReceiver::init(u64 senderSize, u64 recverSize, u64 statSecParam, Channel chl0, NcoOtExtReceiver& otRecv, block seed) {
        std::array<Channel, 1> chans{ chl0 };
        init(senderSize, recverSize, statSecParam, chans, seed);
    }
    void KkrtPsiReceiver::init(u64 senderSize, u64 recverSize, u64 statSecParam, span<Channel> chls, NcoOtExtReceiver& otRecv, block seed) {
        init(senderSize, recverSize, statSecParam, chls, seed);
    }

    void KkrtPsiReceiver::init(u64 senderSize, u64 recverSize, u64 statSecParam, span<Channel> chls, block seed)
    {

        mStatSecParam = statSecParam;
        mSenderSize = senderSize;
        mRecverSize = recverSize;

        mIndex.init(std::max<u64>(200, recverSize), statSecParam, 0,3);

        setTimePoint("kkrt.Recv.Init.start");
        PRNG prng(seed);
        block myHashSeeds;
        myHashSeeds = prng.get<block>();
        auto& chl0 = chls[0];

        chl0.asyncSend((u8*)&myHashSeeds, sizeof(block));
        block theirHashingSeeds;
        chl0.recv((u8*)&theirHashingSeeds, sizeof(block));

        mHashingSeed = myHashSeeds ^ theirHashingSeeds;

        mOtRecvs.resize(chls.size());
        std::thread otThrd[chls.size()];
        for (u64 i = 0; i < chls.size(); i++) {
            block otSeed = prng.get<block>();
            otThrd[i] = std::thread([i, otSeed, this, &chls]() {
                mOtRecvs[i].configure(false, 40, 128);
                PRNG otPrng(otSeed);

                DefaultBaseOT baseBase;
                std::array<block, 128> baseBaseOT;
                BitVector baseBaseChoice(128);
                baseBaseChoice.randomize(otPrng);
                baseBase.receive(baseBaseChoice, baseBaseOT, otPrng, chls[i]);

                IknpOtExtSender base;
                base.setBaseOts(baseBaseOT, baseBaseChoice, chls[i]);
                std::vector<std::array<block, 2>> baseOT(mOtRecvs[i].getBaseOTCount());
                base.send(baseOT, otPrng, chls[i]);

                mOtRecvs[i].setBaseOts(baseOT, otPrng, chls[i]);

                mOtRecvs[i].init(mIndex.mBins.size() + mIndex.mStash.size(), otPrng, chls[i]);
            });
        }

        for (u64 i = 0; i < chls.size(); i++) {
            otThrd[i].join();
        }
    }

    void KkrtPsiReceiver::sendInput(span<block> inputs, Channel & chl)
    {
        std::array<Channel, 1> chls{ chl };
        sendInput(inputs,  chls );
    }

    void KkrtPsiReceiver::sendInput(span<block> inputs, span<Channel> chls)
    {
        // check that the number of inputs is as expected.
        if (inputs.size() != mRecverSize)
            throw std::runtime_error("inputs.size() != mN");
        setTimePoint("kkrt.R Online.Start");

        auto& chl = chls[0];
        auto mOtRecv = &mOtRecvs[0];

        u64 maskByteSize = static_cast<u64>(mStatSecParam + std::log2(mSenderSize * mRecverSize) + 7) / 8;//by byte

        mIndex.insert(inputs, mHashingSeed);


        std::array<std::unordered_map<u64, std::pair<block, u64>>, 3> localMasks;
        localMasks[0].reserve(mIndex.mBins.size()); //upper bound of # mask
        localMasks[1].reserve(mIndex.mBins.size());
        localMasks[2].reserve(mIndex.mBins.size());
        std::vector<std::mutex> mtx_syn(3);


        //======================Bucket BINs (not stash)==========================
        u64 stepSize = 1 << 14;
        setTimePoint("kkrt.R Online.computeBucketMask start");
        std::thread oprfThrd[chls.size()];
        u64 thrdBinSize = std::ceil(1.0 * mIndex.mBins.size() / chls.size());
        std::cout << thrdBinSize * chls.size() << " " << mIndex.mBins.size() << std::endl;
        for (u64 pid = 0; pid < chls.size(); pid++) {
            auto binStart = pid * thrdBinSize;
            auto binEnd = std::min(mIndex.mBins.size(), binStart + thrdBinSize);
            oprfThrd[pid] = std::thread([pid, binStart, maskByteSize, binEnd, &chls, &mtx_syn, stepSize, this, &localMasks, &inputs]() {
                for (u64 stepIdx = binStart; stepIdx < binEnd; stepIdx += stepSize)
                {
                    auto currentStepSize = std::min(stepSize, binEnd - stepIdx);
                    auto stepEnd = stepIdx + currentStepSize;
                    for (u64 bIdx = stepIdx; bIdx < stepEnd; bIdx++)
                    {
                        auto& bin = mIndex.mBins[bIdx];
                        if (bin.isEmpty() == false)
                        {
                            auto idx = bin.idx();
                            auto hIdx = CuckooIndex<>::minCollidingHashIdx(bIdx,mIndex.mHashes[idx], 3, mIndex.mBins.size());
                            auto& item = inputs[idx];
                            block encoding = ZeroBlock;
                            mOtRecvs[pid].encode(bIdx - binStart, &item, &encoding, maskByteSize);
                            mtx_syn[hIdx].lock();
                            localMasks[hIdx].emplace(encoding.as<u64>()[0], std::pair<block, u64>(encoding, idx));
                            mtx_syn[hIdx].unlock();
                        }
                        else
                        {
                            mOtRecvs[pid].zeroEncode(bIdx);
                        }
                    }
                    mOtRecvs[pid].sendCorrection(chls[pid], currentStepSize);
                }
            });
        }

        setTimePoint("kkrt.R Online.sendBucketMask done");
        auto idxSize = std::min<u64>(maskByteSize, sizeof(u64));
        std::array<u64, 3> idxs{ 0,0,0 };

        auto numRegions = (mSenderSize  + stepSize -1) / stepSize;
        auto masksPerRegion = stepSize * 3;
        //std::this_thread::sleep_for(std::chrono::seconds(1));
        Matrix<u8> recvBuff(masksPerRegion, maskByteSize);
        //receive the sender's marks, we have 3 buffs that corresponding to the mask of elements used hash index 0,1,2
        for (u64 regionIdx = 0; regionIdx < numRegions; ++regionIdx)
        {
            auto start = regionIdx * stepSize;
            u64 curStepSize = std::min<u64>(mSenderSize - start, stepSize);
            auto end = start + curStepSize;

            chl.recv(recvBuff.data(), curStepSize * 3 * maskByteSize);

            std::array<u8*, 3>iters{
                recvBuff.data() + 0 * maskByteSize,
                recvBuff.data() + 1 * maskByteSize,
                recvBuff.data() + 2 * maskByteSize };

            for (u64 i = start; i < end; ++i)
            {

                memcpy(idxs.data() + 0, iters[0], idxSize);
                memcpy(idxs.data() + 1, iters[1], idxSize);
                memcpy(idxs.data() + 2, iters[2], idxSize);

                for (u64 k = 0; k < 3; ++k)
                {
                    auto iter = localMasks[k].find(idxs[k]);
                    //std::cout << " find(" << idxs[k] << ") = " << (iter != localMasks[k].end()) <<"   i " << i << " k " << k << std::endl;
                    if (iter != localMasks[k].end() && memcmp(&iter->second.first, iters[k], maskByteSize) == 0)
                    {
                        mIntersection.emplace_back(iter->second.second);
                        //break;
                    }
                }

                iters[0] += 3 * maskByteSize;
                iters[1] += 3 * maskByteSize;
                iters[2] += 3 * maskByteSize;
            }
        }
        setTimePoint("kkrt.R Online.Bucket done");

        for (u64 pid = 0; pid < chls.size(); pid++) {
            oprfThrd[pid].join();
        }
        // u8 dummy[1];
        // chl.recv(dummy, 1);
    }
}
#endif