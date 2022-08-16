
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

        //u64 codeWordSize = get_codeword_size(std::max<u64>(mSenderSize, mRecverSize)); //by byte
        u64 maskByteSize = static_cast<u64>(mStatSecParam + std::log2(mSenderSize * mRecverSize) + 7) / 8;//by byte

        //insert item to corresponding bin
        mIndex.insert(inputs, mHashingSeed);


        //we use 4 unordered_maps, we put the mask to the corresponding unordered_map
        //that indicates of the hash function index 0,1,2. and the last unordered_maps is used for stash bin
        std::array<std::unordered_map<u64, std::pair<block, u64>>, 3> localMasks;
        //store the masks of elements that map to bin by h0
        localMasks[0].reserve(mIndex.mBins.size()); //upper bound of # mask
        //store the masks of elements that map to bin by h1
        localMasks[1].reserve(mIndex.mBins.size());
        //store the masks of elements that map to bin by h2
        localMasks[2].reserve(mIndex.mBins.size());


        //======================Bucket BINs (not stash)==========================

        //pipelining the execution of the online phase (i.e., OT correction step) into multiple batches
        auto binStart = 0;
        auto binEnd = mIndex.mBins.size();
        setTimePoint("kkrt.R Online.computeBucketMask start");
        u64 stepSize = 1 << 10;

        //for each batch
        for (u64 stepIdx = binStart; stepIdx < binEnd; stepIdx += stepSize)
        {
            // compute the size of current step & end index.
            auto currentStepSize = std::min(stepSize, binEnd - stepIdx);
            auto stepEnd = stepIdx + currentStepSize;

            // for each bin, do encoding
            for (u64 bIdx = stepIdx, i = 0; bIdx < stepEnd; bIdx++, ++i)
            {
                //block mask(ZeroBlock);
                auto& bin = mIndex.mBins[bIdx];

                if (bin.isEmpty() == false)
                {
                    auto idx = bin.idx();

                    // get the smallest hash function index that maps this item to this bin.
                    auto hIdx = CuckooIndex<>::minCollidingHashIdx(bIdx,mIndex.mHashes[idx], 3, mIndex.mBins.size());

                    auto& item = inputs[idx];

                    block encoding = ZeroBlock;

                    mOtRecv->encode(bIdx, &item, &encoding, maskByteSize);

                    //std::cout << "r input[" << idx << "] = " << inputs[idx] << " h = " << (int)hIdx << " bIdx = " << bIdx << " -> " << *(u64*)&encoding << std::endl;

                    //store my mask into corresponding buff at the permuted position
                    localMasks[hIdx].emplace(encoding.as<u64>()[0], std::pair<block, u64>(encoding, idx));
                }
                else
                {
                    // no item for this bin, just use a dummy.
                    mOtRecv->zeroEncode(bIdx);
                }
            }
            // send the OT correction masks for the current step

            mOtRecv->sendCorrection(chl, currentStepSize);
        }// Done with compute the masks for the main set of bins.

        setTimePoint("kkrt.R Online.sendBucketMask done");


        //u64 sendCount = (mSenderSize + stepSize - 1) / stepSize;
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

        // u8 dummy[1];
        // chl.recv(dummy, 1);
    }
}
#endif