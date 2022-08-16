
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
        prngs.resize(chls.size());
        std::thread otThrd[chls.size()];
        for (u64 i = 0; i < chls.size(); i++) {
            prngs[i] = PRNG(prng.get<block>());
            otThrd[i] = std::thread([i, this, &chls]() {
                mOtRecvs[i].configure(false, 40, 128);

                DefaultBaseOT baseBase;
                std::array<block, 128> baseBaseOT;
                BitVector baseBaseChoice(128);
                baseBaseChoice.randomize(prngs[i]);
                baseBase.receive(baseBaseChoice, baseBaseOT, prngs[i], chls[i]);

                IknpOtExtSender base;
                base.setBaseOts(baseBaseOT, baseBaseChoice, chls[i]);
                std::vector<std::array<block, 2>> baseOT(mOtRecvs[i].getBaseOTCount());
                base.send(baseOT, prngs[i], chls[i]);

                mOtRecvs[i].setBaseOts(baseOT, prngs[i], chls[i]);
                std::array<block, 4> keys;
                PRNG(mHashingSeed).get(keys.data(), keys.size());
                mOtRecvs[i].mMultiKeyAES.setKeys(keys);
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
        for (u64 pid = 0; pid < chls.size(); pid++) {
            auto binStart = pid * thrdBinSize;
            auto binEnd = std::min(mIndex.mBins.size(), binStart + thrdBinSize);
            oprfThrd[pid] = std::thread([pid, binStart, maskByteSize, binEnd, &chls, &mtx_syn, stepSize, this, &localMasks, &inputs]() {
                for (u64 stepIdx = binStart; stepIdx < binEnd; stepIdx += stepSize)
                {
                    auto currentStepSize = std::min(stepSize, binEnd - stepIdx);
                    auto stepEnd = stepIdx + currentStepSize;
                    mOtRecvs[pid].init(currentStepSize, prngs[pid], chls[pid]);
                    for (u64 bIdx = stepIdx; bIdx < stepEnd; bIdx++)
                    {
                        auto& bin = mIndex.mBins[bIdx];
                        if (bin.isEmpty() == false)
                        {
                            auto idx = bin.idx();
                            auto hIdx = CuckooIndex<>::minCollidingHashIdx(bIdx,mIndex.mHashes[idx], 3, mIndex.mBins.size());
                            auto& item = inputs[idx];
                            block encoding = ZeroBlock;
                            mOtRecvs[pid].encode(bIdx - stepIdx, &item, &encoding, maskByteSize);
                            mtx_syn[hIdx].lock();
                            localMasks[hIdx].emplace(encoding.as<u64>()[0], std::pair<block, u64>(encoding, idx));
                            mtx_syn[hIdx].unlock();
                        }
                        else
                        {
                            mOtRecvs[pid].zeroEncode(bIdx - stepIdx);
                        }
                    }
                    mOtRecvs[pid].sendCorrection(chls[pid], currentStepSize);
                }
            });
        }
        for (u64 pid = 0; pid < chls.size(); pid++) {
            oprfThrd[pid].join();
        }
        setTimePoint("kkrt.R Online.sendBucketMask done");

        std::thread maskThrd[chls.size()];
        u64 thrdDataSize = std::ceil(1.0 * inputs.size() / chls.size());
        std::vector<std::vector<u64>> thrdIntersections(chls.size());
        for (u64 pid = 0; pid < chls.size(); pid++) {
            auto inputStart = pid * thrdDataSize;
            auto inputEnd = std::min(inputs.size(), inputStart + thrdDataSize);
            maskThrd[pid] = std::thread([pid, inputStart, &thrdIntersections, maskByteSize, &chls, inputEnd, stepSize, &localMasks, this]() {
                Matrix<u8> myMaskBuff(stepSize * mIndex.mParams.mNumHashes, maskByteSize);
                for (u64 inputId = inputStart; inputId < inputEnd; inputId += stepSize)
                {
                    auto currentStepSize = std::min(stepSize, inputEnd - inputId);
                    auto size = myMaskBuff.stride() * currentStepSize * mIndex.mParams.mNumHashes;
                    chls[pid].recv(myMaskBuff.data(), size);

                    auto idxSize = std::min<u64>(maskByteSize, sizeof(u64));
                    auto data = myMaskBuff.data();
                    u64 idxs;
                    for (u64 i = 0; i < currentStepSize; ++i)
                    {
                        for (u64 k = 0; k < 3; ++k)
                        {
                            memcpy(&idxs, data, idxSize);
                            auto iter = localMasks[k].find(idxs);
                            if (iter != localMasks[k].end() && memcmp(&iter->second.first, data, maskByteSize) == 0)
                            {
                                thrdIntersections[pid].emplace_back(iter->second.second);
                            }
                            data += maskByteSize;
                        }
                    }
                }
            });
        }

        for (u64 pid = 0; pid < chls.size(); pid++) {
            maskThrd[pid].join();
            mIntersection.insert(mIntersection.end(), thrdIntersections[pid].begin(), thrdIntersections[pid].end());
        }

        setTimePoint("kkrt.R Online.Bucket done");

    }
}
#endif


