
#include "libPSI/config.h"
#ifdef ENABLE_KKRT_PSI
#include "KkrtPsiSender.h"
#include "cryptoTools/Crypto/Commit.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/Timer.h"
#include "libOTe/Base/BaseOT.h"
#include "libOTe/TwoChooseOne/IknpOtExtReceiver.h"
#include <cryptoTools/Common/Matrix.h>
#include "cryptoTools/Common/CuckooIndex.h"
//#include <unordered_map>
#include "libPSI/Tools/SimpleIndex.h"
#include <condition_variable>
#include <mutex>


namespace osuCrypto
{

    KkrtPsiSender::KkrtPsiSender()
    {
    }

    KkrtPsiSender::~KkrtPsiSender()
    {
    }
    //extern std::string hexString(u8* data, u64 length);

    void KkrtPsiSender::init(u64 senderSize, u64 recverSize, u64 statSec, Channel & chl0, block seed)
    {
        std::array<Channel, 1> c{ chl0 };
        init(senderSize, recverSize, statSec, c, seed);
    }

    void KkrtPsiSender::init(u64 senderSize, u64 recverSize, u64 statSec, Channel & chl0, NcoOtExtSender& ots, block seed)
    {
        std::array<Channel, 1> c{ chl0 };
        init(senderSize, recverSize, statSec, c, seed);
    }

    void KkrtPsiSender::init(u64 senderSize, u64 recverSize, u64 statSec, span<Channel> chls, NcoOtExtSender& ots, block seed)
    {
        init(senderSize, recverSize, statSec, chls, seed);
    }

    void KkrtPsiSender::init(u64 senderSize, u64 recverSize, u64 statSec, span<Channel> chls, block seed)
    {
        mStatSecParam = statSec;
        mSenderSize = senderSize;
        mRecverSize = recverSize;

        mPrng.SetSeed(seed);
        block myHashSeeds;
        myHashSeeds = mPrng.get<block>();
        auto& chl = chls[0];
        chl.asyncSend((u8*)&myHashSeeds, sizeof(block));

        block theirHashingSeeds;
        chl.recv((u8*)&theirHashingSeeds, sizeof(block));
        mHashingSeed = myHashSeeds ^ theirHashingSeeds;

        mParams = CuckooIndex<>::selectParams(std::max<u64>(200, recverSize), statSec, 0,3);
        if (mParams.mNumHashes != 3) throw std::runtime_error(LOCATION);

        mOtSenders.resize(chls.size());
        prngs.resize(chls.size());
        std::thread otThrd[chls.size()];
        for (u64 i = 0; i < chls.size(); i++) {
            prngs[i] = PRNG(mPrng.get<block>());
            otThrd[i] = std::thread([i, this, &chls]() {
                mOtSenders[i].configure(false, 40, 128);

                DefaultBaseOT baseBase;
                std::array<std::array<block, 2>, 128> baseBaseOT;
                baseBase.send(baseBaseOT, prngs[i], chls[i]);

                IknpOtExtReceiver base;
                base.setBaseOts(baseBaseOT, prngs[i], chls[i]);

                BitVector baseChoice(mOtSenders[i].getBaseOTCount());
                baseChoice.randomize(prngs[i]);
                std::vector<block> baseOT(mOtSenders[i].getBaseOTCount());
                base.receive(baseChoice, baseOT, prngs[i], chls[i]);

                mOtSenders[i].setBaseOts(baseOT, baseChoice, chls[i]);
                std::array<block, 4> keys;
                PRNG(mHashingSeed).get(keys.data(), keys.size());
                mOtSenders[i].mMultiKeyAES.setKeys(keys);
            });
        }
        
        setTimePoint("kkrt.S offline.perm start");
        mPermute.resize(mSenderSize);
        for (u64 i = 0; i < mSenderSize; ++i) mPermute[i] = i;

        std::shuffle(mPermute.begin(), mPermute.end(), mPrng);

        setTimePoint("kkrt.S offline.perm done");

        for (u64 i = 0; i < chls.size(); i++) {
            otThrd[i].join();
        }
    }


    void KkrtPsiSender::sendInput(span<block> inputs, Channel & chl)
    {
        std::array<Channel, 1> chls{ chl };
        sendInput(inputs, chls);
    }








    void hashItems(
        span<block> items,
        MatrixView<u64> mItemToBinMap,
        block hashingSeed,
        u64 numBins,
        PRNG& prng,
        MatrixView<u8> masks,
        span<u64> perm)
    {

        std::array<block, 8> hashs;
        AES hasher(hashingSeed);

        auto mNumHashFunctions = mItemToBinMap.stride();
        auto mainSteps = items.size() / hashs.size();
        auto remSteps = items.size() % hashs.size();
        u64 itemIdx = 0;

        if (mNumHashFunctions == 3)
        {

            std::array<PRNG, 8> prngs;
            for (u64 i = 0; i < 8; ++i)
                prngs[i].SetSeed(prng.get<block>());

            for (u64 i = 0; i < mainSteps; ++i, itemIdx += 8)
            {
                hasher.ecbEncBlocks(items.data() + itemIdx, 8, hashs.data());

                auto itemIdx0 = itemIdx + 0;
                auto itemIdx1 = itemIdx + 1;
                auto itemIdx2 = itemIdx + 2;
                auto itemIdx3 = itemIdx + 3;
                auto itemIdx4 = itemIdx + 4;
                auto itemIdx5 = itemIdx + 5;
                auto itemIdx6 = itemIdx + 6;
                auto itemIdx7 = itemIdx + 7;

                // compute the hash as  H(x) = AES(x) + x
                hashs[0] = hashs[0] ^ items[itemIdx0];
                hashs[1] = hashs[1] ^ items[itemIdx1];
                hashs[2] = hashs[2] ^ items[itemIdx2];
                hashs[3] = hashs[3] ^ items[itemIdx3];
                hashs[4] = hashs[4] ^ items[itemIdx4];
                hashs[5] = hashs[5] ^ items[itemIdx5];
                hashs[6] = hashs[6] ^ items[itemIdx6];
                hashs[7] = hashs[7] ^ items[itemIdx7];

                // Get the first bin that each of the items maps to
                auto bIdx00 = CuckooIndex<>::getHash(hashs[0], 0, numBins);
                auto bIdx10 = CuckooIndex<>::getHash(hashs[1], 0, numBins);
                auto bIdx20 = CuckooIndex<>::getHash(hashs[2], 0, numBins);
                auto bIdx30 = CuckooIndex<>::getHash(hashs[3], 0, numBins);
                auto bIdx40 = CuckooIndex<>::getHash(hashs[4], 0, numBins);
                auto bIdx50 = CuckooIndex<>::getHash(hashs[5], 0, numBins);
                auto bIdx60 = CuckooIndex<>::getHash(hashs[6], 0, numBins);
                auto bIdx70 = CuckooIndex<>::getHash(hashs[7], 0, numBins);

                // update the map with these bin indexes
                mItemToBinMap(itemIdx0, 0) = bIdx00;
                mItemToBinMap(itemIdx1, 0) = bIdx10;
                mItemToBinMap(itemIdx2, 0) = bIdx20;
                mItemToBinMap(itemIdx3, 0) = bIdx30;
                mItemToBinMap(itemIdx4, 0) = bIdx40;
                mItemToBinMap(itemIdx5, 0) = bIdx50;
                mItemToBinMap(itemIdx6, 0) = bIdx60;
                mItemToBinMap(itemIdx7, 0) = bIdx70;

                // get the second bin index
                auto bIdx01 = CuckooIndex<>::getHash(hashs[0], 1, numBins);
                auto bIdx11 = CuckooIndex<>::getHash(hashs[1], 1, numBins);
                auto bIdx21 = CuckooIndex<>::getHash(hashs[2], 1, numBins);
                auto bIdx31 = CuckooIndex<>::getHash(hashs[3], 1, numBins);
                auto bIdx41 = CuckooIndex<>::getHash(hashs[4], 1, numBins);
                auto bIdx51 = CuckooIndex<>::getHash(hashs[5], 1, numBins);
                auto bIdx61 = CuckooIndex<>::getHash(hashs[6], 1, numBins);
                auto bIdx71 = CuckooIndex<>::getHash(hashs[7], 1, numBins);

                // check if we get a collision with the first bin index
                u8 c01 = 1 & (bIdx00 == bIdx01);
                u8 c11 = 1 & (bIdx10 == bIdx11);
                u8 c21 = 1 & (bIdx20 == bIdx21);
                u8 c31 = 1 & (bIdx30 == bIdx31);
                u8 c41 = 1 & (bIdx40 == bIdx41);
                u8 c51 = 1 & (bIdx50 == bIdx51);
                u8 c61 = 1 & (bIdx60 == bIdx61);
                u8 c71 = 1 & (bIdx70 == bIdx71);

                // If we didnt get a collision, set the new bin index and otherwise set it to -1
                mItemToBinMap(itemIdx0, 1) = bIdx01 | (c01 * u64(-1));
                mItemToBinMap(itemIdx1, 1) = bIdx11 | (c11 * u64(-1));
                mItemToBinMap(itemIdx2, 1) = bIdx21 | (c21 * u64(-1));
                mItemToBinMap(itemIdx3, 1) = bIdx31 | (c31 * u64(-1));
                mItemToBinMap(itemIdx4, 1) = bIdx41 | (c41 * u64(-1));
                mItemToBinMap(itemIdx5, 1) = bIdx51 | (c51 * u64(-1));
                mItemToBinMap(itemIdx6, 1) = bIdx61 | (c61 * u64(-1));
                mItemToBinMap(itemIdx7, 1) = bIdx71 | (c71 * u64(-1));

                // if we got a collision, then fill the final mask locations with junk data
                prngs[0].get(masks.data() + (perm[itemIdx0] * mNumHashFunctions + 1) * masks.stride(), c01 * masks.stride());
                prngs[1].get(masks.data() + (perm[itemIdx1] * mNumHashFunctions + 1) * masks.stride(), c11 * masks.stride());
                prngs[2].get(masks.data() + (perm[itemIdx2] * mNumHashFunctions + 1) * masks.stride(), c21 * masks.stride());
                prngs[3].get(masks.data() + (perm[itemIdx3] * mNumHashFunctions + 1) * masks.stride(), c31 * masks.stride());
                prngs[4].get(masks.data() + (perm[itemIdx4] * mNumHashFunctions + 1) * masks.stride(), c41 * masks.stride());
                prngs[5].get(masks.data() + (perm[itemIdx5] * mNumHashFunctions + 1) * masks.stride(), c51 * masks.stride());
                prngs[6].get(masks.data() + (perm[itemIdx6] * mNumHashFunctions + 1) * masks.stride(), c61 * masks.stride());
                prngs[7].get(masks.data() + (perm[itemIdx7] * mNumHashFunctions + 1) * masks.stride(), c71 * masks.stride());


                // repeat the process with the last hash function
                auto bIdx02 = CuckooIndex<>::getHash(hashs[0], 2, numBins);
                auto bIdx12 = CuckooIndex<>::getHash(hashs[1], 2, numBins);
                auto bIdx22 = CuckooIndex<>::getHash(hashs[2], 2, numBins);
                auto bIdx32 = CuckooIndex<>::getHash(hashs[3], 2, numBins);
                auto bIdx42 = CuckooIndex<>::getHash(hashs[4], 2, numBins);
                auto bIdx52 = CuckooIndex<>::getHash(hashs[5], 2, numBins);
                auto bIdx62 = CuckooIndex<>::getHash(hashs[6], 2, numBins);
                auto bIdx72 = CuckooIndex<>::getHash(hashs[7], 2, numBins);


                u8 c02 = 1 & (bIdx00 == bIdx02 || bIdx01 == bIdx02);
                u8 c12 = 1 & (bIdx10 == bIdx12 || bIdx11 == bIdx12);
                u8 c22 = 1 & (bIdx20 == bIdx22 || bIdx21 == bIdx22);
                u8 c32 = 1 & (bIdx30 == bIdx32 || bIdx31 == bIdx32);
                u8 c42 = 1 & (bIdx40 == bIdx42 || bIdx41 == bIdx42);
                u8 c52 = 1 & (bIdx50 == bIdx52 || bIdx51 == bIdx52);
                u8 c62 = 1 & (bIdx60 == bIdx62 || bIdx61 == bIdx62);
                u8 c72 = 1 & (bIdx70 == bIdx72 || bIdx71 == bIdx72);


                mItemToBinMap(itemIdx0, 2) = bIdx02 | (c02 * u64(-1));
                mItemToBinMap(itemIdx1, 2) = bIdx12 | (c12 * u64(-1));
                mItemToBinMap(itemIdx2, 2) = bIdx22 | (c22 * u64(-1));
                mItemToBinMap(itemIdx3, 2) = bIdx32 | (c32 * u64(-1));
                mItemToBinMap(itemIdx4, 2) = bIdx42 | (c42 * u64(-1));
                mItemToBinMap(itemIdx5, 2) = bIdx52 | (c52 * u64(-1));
                mItemToBinMap(itemIdx6, 2) = bIdx62 | (c62 * u64(-1));
                mItemToBinMap(itemIdx7, 2) = bIdx72 | (c72 * u64(-1));

                prngs[0].get(masks.data() + (perm[itemIdx0] * mNumHashFunctions + 2) * masks.stride(), c01 * masks.stride());
                prngs[1].get(masks.data() + (perm[itemIdx1] * mNumHashFunctions + 2) * masks.stride(), c11 * masks.stride());
                prngs[2].get(masks.data() + (perm[itemIdx2] * mNumHashFunctions + 2) * masks.stride(), c21 * masks.stride());
                prngs[3].get(masks.data() + (perm[itemIdx3] * mNumHashFunctions + 2) * masks.stride(), c31 * masks.stride());
                prngs[4].get(masks.data() + (perm[itemIdx4] * mNumHashFunctions + 2) * masks.stride(), c41 * masks.stride());
                prngs[5].get(masks.data() + (perm[itemIdx5] * mNumHashFunctions + 2) * masks.stride(), c51 * masks.stride());
                prngs[6].get(masks.data() + (perm[itemIdx6] * mNumHashFunctions + 2) * masks.stride(), c61 * masks.stride());
                prngs[7].get(masks.data() + (perm[itemIdx7] * mNumHashFunctions + 2) * masks.stride(), c71 * masks.stride());
            }

            // in case the input does not divide evenly by 8, handle the last few items.
            hasher.ecbEncBlocks(items.data() + itemIdx, remSteps, hashs.data());
            for (u64 i = 0; i < remSteps; ++i, ++itemIdx)
            {
                hashs[i] = hashs[i] ^ items[itemIdx];

                std::vector<u64> bIdxs(mNumHashFunctions);
                for (u64 h = 0; h < mNumHashFunctions; ++h)
                {
                    auto bIdx = CuckooIndex<>::getHash(hashs[i], (u8)h, numBins);
                    bool collision = false;

                    bIdxs[h] = bIdx;
                    for (u64 hh = 0; hh < h; ++hh)
                        collision |= (bIdxs[hh] == bIdx);

                    u8 c = ((u8)collision & 1);
                    mItemToBinMap(itemIdx, h) = bIdx | c * u64(-1);
                    prng.get(masks.data() + (perm[itemIdx] * mNumHashFunctions + h) * masks.stride(), c * masks.stride());
                }
            }
        }
        else
        {
            // general procedure for when numHashes != 3
            std::vector<u64> bIdxs(mNumHashFunctions);
            for (u64 i = 0; i < items.size(); i += hashs.size())
            {
                auto min = std::min<u64>(items.size() - i, hashs.size());

                hasher.ecbEncBlocks(items.data() + i, min, hashs.data());

                for (u64 j = 0, itemIdx = i; j < min; ++j, ++itemIdx)
                {
                    hashs[j] = hashs[j] ^ items[itemIdx];

                    for (u64 h = 0; h < mNumHashFunctions; ++h)
                    {
                        auto bIdx = CuckooIndex<>::getHash(hashs[j], (u8)h, numBins);
                        bool collision = false;

                        bIdxs[h] = bIdx;
                        for (u64 hh = 0; hh < h; ++hh)
                            collision |= (bIdxs[hh] == bIdx);
                        u8 c = ((u8)collision & 1);
                        mItemToBinMap(itemIdx, h) = bIdx | c * u64(-1);
                        prng.get(masks.data() + (perm[itemIdx] * mNumHashFunctions + h) * masks.stride(), c * masks.stride());

                    }
                }
            }
        }
    }





    void hashBinItems(
        span<block> items,
        block hashingSeed,
        u64 numBins,
        PRNG& prng,
        MatrixView<u8> masks,
        span<u64> perm,
        u64 numHashes,
        span<u64> binIndex,
        span<u64> binIdx,
        span<u8> binHash
    ) {
        Matrix<u64> binIdxs(items.size(), numHashes);
        hashItems(items, binIdxs, hashingSeed, numBins, prng, masks, perm);
        
        for (u64 i = 0; i < items.size(); i++) {
            for (u64 j = 0; j < numHashes; j++) {
                auto bid = binIdxs(i, j);
                if (bid != -1) {
                    binIndex[bid]++;
                } 
            }
        }
        for (u64 i = 1; i < numBins; i++) {
            binIndex[i] += binIndex[i - 1];
        }
        binIndex[numBins] = binIndex[numBins - 1];
        for (u64 i = 0; i < items.size(); i++) {
            for (u64 j = 0; j < numHashes; j++) {
                auto bid = binIdxs(i, j);
                if (bid != -1) {
                    auto tIndex = --binIndex[bid];
                    binIdx[tIndex] = i;
                    binHash[tIndex] = j;
                }
            }
        }
    }





    void KkrtPsiSender::sendInput(span<block> inputs, span<Channel> chls)
    {
        if (inputs.size() != mSenderSize)
            throw std::runtime_error("rt error at " LOCATION);

        setTimePoint("kkrt.S Online.online start");

        u64 maskSize = u64(mStatSecParam + std::log2(mSenderSize * mRecverSize) + 7) / 8; //by byte
        auto numBins = mParams.numBins();

        Matrix<u8> myMaskBuff(mSenderSize * mParams.mNumHashes, maskSize);

        
        setTimePoint("kkrt.S Online.hashing start");

        std::vector<u64> binIndex(numBins + 1);
        std::vector<u64> binIdx(mParams.mNumHashes * numBins);
        std::vector<u8> binHash(mParams.mNumHashes * numBins);
        hashBinItems(inputs, mHashingSeed, numBins, mPrng, myMaskBuff, mPermute, mParams.mNumHashes, binIndex, binIdx, binHash);

        u64 stepSize = 1 << 14;
        setTimePoint("kkrt.S Online.linear start");
        std::thread oprfThrd[chls.size()];
        u64 thrdBinSize = std::ceil(1.0 * numBins / chls.size());
        for (u64 pid = 0; pid < chls.size(); pid++) {
            auto binStart = pid * thrdBinSize;
            auto binEnd = std::min(numBins, binStart + thrdBinSize);
            oprfThrd[pid] = std::thread([pid, binStart, &chls, binEnd, &inputs, stepSize, this, &myMaskBuff, &binIndex, &binIdx, &binHash]() {
                std::atomic<u64> recvedIdx(binStart);
                std::mutex mtx_syn, mtx_que;
                std::condition_variable cv_syn;
                std::queue<u8 *> recvQue;
                u64 corByte = 456 / 8;
                // u64 corByte = sizeof(block) * mOtSenders[pid].mGens.size() / 128;
                auto thrd = std::thread([&]() {
                    while (recvedIdx < binEnd)
                    {
                        auto currentStepSize = std::min(stepSize, binEnd - recvedIdx);
                        u8* buffer = new u8[currentStepSize * corByte];
                        // recv指定长度
                        chls[pid].recv(buffer, currentStepSize * corByte);

                        mtx_que.lock();
                        recvQue.push(buffer);
                        mtx_que.unlock();

                        recvedIdx.fetch_add(currentStepSize, std::memory_order::memory_order_release);
                        cv_syn.notify_one();
                    }
                });
                std::unique_lock<std::mutex> lck(mtx_syn);
                for (u64 stepIdx = binStart; stepIdx < binEnd; stepIdx += stepSize) {
                    cv_syn.wait(lck, [stepIdx, &recvedIdx]{
                        return stepIdx < recvedIdx.load(std::memory_order::memory_order_acquire);
                    });
                    auto currentStepSize = std::min(stepSize, binEnd - stepIdx);
                                            
                    mOtSenders[pid].init(currentStepSize, prngs[pid], chls[pid]);
                    mtx_que.lock();
                    u8 * buffer = recvQue.front();
                    recvQue.pop();
                    mtx_que.unlock();

                    u64 otCorStride = mOtSenders[pid].mCorrectionVals.stride();
                    auto dest = mOtSenders[pid].mCorrectionVals.begin() + (mOtSenders[pid].mCorrectionIdx * otCorStride);
                    for (int i = 0; i < currentStepSize; i++) {
                        memcpy((u8*)&*dest, buffer + i * corByte, corByte);
                        dest += otCorStride;
                    }
                    mOtSenders[pid].mCorrectionIdx += currentStepSize;

                    delete[] buffer;

                    auto stepEnd = stepIdx + currentStepSize;
                    for (u64 bIdx = stepIdx; bIdx < stepEnd; bIdx++)
                    {    
                        for (u64 start = binIndex[bIdx]; start < binIndex[bIdx + 1]; start++) {
                            auto inputIdx = binIdx[start];
                            auto inputHash = binHash[start];
                            mOtSenders[pid].encode(bIdx - stepIdx, &inputs[inputIdx], 
                                    myMaskBuff.data() + myMaskBuff.stride() * (mPermute[inputIdx] * mParams.mNumHashes + inputHash), 
                                    myMaskBuff.stride());
                        }
                    }
                }
                thrd.join();
            });
        }
        for (u64 pid = 0; pid < chls.size(); pid++) {
            oprfThrd[pid].join();
        }

        setTimePoint("kkrt.S Online.send start");
        std::thread maskThrd[chls.size()];
        u64 thrdDataSize = std::ceil(1.0 * inputs.size() / chls.size());
        for (u64 pid = 0; pid < chls.size(); pid++) {
            auto inputStart = pid * thrdDataSize;
            auto inputEnd = std::min(inputs.size(), inputStart + thrdDataSize);
            maskThrd[pid] = std::thread([pid, inputStart, &chls, inputEnd, &myMaskBuff, stepSize, this]() {
                for (u64 inputId = inputStart; inputId < inputEnd; inputId += stepSize)
                {
                    auto currentStepSize = std::min(stepSize, inputEnd - inputId);
                    auto data = myMaskBuff.data() + myMaskBuff.stride() * inputId * mParams.mNumHashes;
                    auto size = myMaskBuff.stride() * currentStepSize * mParams.mNumHashes;
                    chls[pid].asyncSendCopy(data, size);
                }
            });
        }
        for (u64 pid = 0; pid < chls.size(); pid++) {
            maskThrd[pid].join();
        }
        
        setTimePoint("kkrt.S Online.done start");

    }
}


#endif








                // std::atomic<u64> recvedIdx(binStart);
                // std::mutex mtx_syn, mtx_que;
                // std::condition_variable cv_syn;
                // std::queue<u8 *> recvQue;
                // auto thrd = std::thread([&]() {
                //     while (recvedIdx < binEnd)
                //     {
                //         auto currentStepSize = std::min(stepSize, binEnd - recvedIdx);
                //         u8* buffer = new u8[stepSize * sizeof(block) * 4];
                //         chls[pid].recv(buffer, currentStepSize * sizeof(block) * 4);

                //         mtx_que.lock();
                //         recvQue.push(buffer);
                //         mtx_que.unlock();

                //         recvedIdx.fetch_add(currentStepSize, std::memory_order::memory_order_release);
                //         cv_syn.notify_one();
                //     }
                // });
                // std::unique_lock<std::mutex> lck(mtx_syn);
                // for (u64 stepIdx = binStart; stepIdx < binEnd; stepIdx += stepSize) {
                //     cv_syn.wait(lck, [stepIdx, &recvedIdx]{
                //         return stepIdx < recvedIdx.load(std::memory_order::memory_order_acquire);
                //     });
                //     auto currentStepSize = std::min(stepSize, binEnd - stepIdx);
                                            
                //     mOtSenders[pid].init(currentStepSize, prngs[pid], chls[pid]);
                //     mtx_que.lock();
                //     u8 * buffer = recvQue.front();
                //     recvQue.pop();
                //     mtx_que.unlock();
                //     auto dest = mOtSenders[pid].mCorrectionVals.begin() + (mOtSenders[pid].mCorrectionIdx * 4);
                //     memcpy((u8*)&*dest, buffer, currentStepSize * sizeof(block) * 4);
                //     mOtSenders[pid].mCorrectionIdx += currentStepSize;
                //     delete[] buffer;

                //     auto stepEnd = stepIdx + currentStepSize;
                //     for (u64 bIdx = stepIdx; bIdx < stepEnd; bIdx++)
                //     {    
                //         for (u64 start = binIndex[bIdx]; start < binIndex[bIdx + 1]; start++) {
                //             auto inputIdx = binIdx[start];
                //             auto inputHash = binHash[start];
                //             mOtSenders[pid].encode(bIdx - stepIdx, &inputs[inputIdx], 
                //                     myMaskBuff.data() + myMaskBuff.stride() * (mPermute[inputIdx] * mParams.mNumHashes + inputHash), 
                //                     myMaskBuff.stride());
                //         }
                //     }
                // }
                // thrd.join();


            // oprfThrd[pid] = std::thread([pid, binStart, &chls, binEnd, &inputs, stepSize, this, &myMaskBuff, &binIndex, &binIdx, &binHash]() {
            //     u64 recvedIdx = binStart;
            //     while (recvedIdx < binEnd)
            //     {
            //         auto currentStepSize = std::min(stepSize, binEnd - recvedIdx);
                        
            //         mOtSenders[pid].init(currentStepSize, prngs[pid], chls[pid]);
            //         mOtSenders[pid].recvCorrection(chls[pid], currentStepSize);

            //         auto stepEnd = recvedIdx + currentStepSize;
            //         for (u64 bIdx = recvedIdx; bIdx < stepEnd; bIdx++) 
            //         {
            //             for (u64 start = binIndex[bIdx]; start < binIndex[bIdx + 1]; start++) {
            //                 auto inputIdx = binIdx[start];
            //                 auto inputHash = binHash[start];
            //                 mOtSenders[pid].encode(bIdx - recvedIdx, &inputs[inputIdx], 
            //                         myMaskBuff.data() + myMaskBuff.stride() * (mPermute[inputIdx] * mParams.mNumHashes + inputHash), 
            //                         myMaskBuff.stride());
            //             }
            //         }

            //         recvedIdx.fetch_add(currentStepSize, std::memory_order::memory_order_release);
            //     }
            // });