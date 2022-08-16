#pragma once

#include "libPSI/config.h"
#ifdef ENABLE_KKRT_PSI

#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Network/Channel.h"
#include "libOTe/NChooseOne/NcoOtExt.h"
#include "libPSI/Tools/CuckooHasher.h"
#include "cryptoTools/Common/CuckooIndex.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"

namespace osuCrypto
{

    class KkrtPsiReceiver : public TimerAdapter
    {
    public:
        KkrtPsiReceiver();
        ~KkrtPsiReceiver();

        u64 mRecverSize,mSenderSize,mStatSecParam;
        std::vector<u64> mIntersection;
        CuckooIndex<NotThreadSafe> mIndex;

        std::vector<KkrtNcoOtReceiver> mOtRecvs;

        block mHashingSeed;
        
        void init(u64 senderSize, u64 recverSize, u64 statSecParam, Channel chl0, block seed);
        void init(u64 senderSize, u64 recverSize, u64 statSecParam, span<Channel> chls, block seed);
        void init(u64 senderSize, u64 recverSize, u64 statSecParam, Channel chl0, NcoOtExtReceiver& otRecv, block seed);
        void init(u64 senderSize, u64 recverSize, u64 statSecParam, span<Channel> chls, NcoOtExtReceiver& otRecv, block seed);
        void sendInput(span<block> inputs, Channel& chl);
        void sendInput(span<block> inputs, span<Channel> chls);

    };




}
#endif