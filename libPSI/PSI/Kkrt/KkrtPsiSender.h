#pragma once

#include "libPSI/config.h"
#ifdef ENABLE_KKRT_PSI

#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Network/Channel.h>
#include <libOTe/NChooseOne/NcoOtExt.h>
#include "cryptoTools/Crypto/PRNG.h"
#include <cryptoTools/Common/CuckooIndex.h>
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"

namespace osuCrypto
{


	class KkrtPsiSender : public TimerAdapter
	{
	public:
		KkrtPsiSender();
		~KkrtPsiSender();

		u64 mSenderSize, mRecverSize, mStatSecParam;
        PRNG mPrng;
		std::vector<PRNG> prngs;
        std::vector<u64> mPermute;

		//SimpleIndex mIndex;
        CuckooParam mParams;
		block mHashingSeed;

        std::vector<KkrtNcoOtSender> mOtSenders;

		void init(u64 senderSize, u64 recverSize, u64 statSecParam, span<Channel> chls, block seed);
		void init(u64 senderSize, u64 recverSize, u64 statSecParam, Channel & chl0, block seed);

		void init(u64 senderSize, u64 recverSize, u64 statSecParam, span<Channel> chls, NcoOtExtSender& ots, block seed);
		void init(u64 senderSize, u64 recverSize, u64 statSecParam, Channel & chl0, NcoOtExtSender& ots, block seed);

		void sendInput(span<block> inputs, Channel& chl);
		void sendInput(span<block> inputs, span<Channel> chls);


	};

}
#endif