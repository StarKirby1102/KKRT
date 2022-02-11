//#pragma once

#include "libOTe/libOTe/TwoChooseOne/OTExtInterface.h"

#include "libOTe/libOTe/Tools/Tools.h"
#include "libOTe/libOTe/Tools/LinearCode.h"
#include <libOTe/cryptoTools/cryptoTools/Network/Channel.h>
#include <libOTe/cryptoTools/cryptoTools/Network/Session.h>
#include <libOTe/cryptoTools/cryptoTools/Network/IOService.h>
#include <libOTe/cryptoTools/cryptoTools/Common/Log.h>

#include "libOTe/libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "libOTe/libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"
using namespace std;
using namespace osuCrypto;

void test_KKRT(){
    setThreadName("Sender");
        
    PRNG prng0(block(4253465, 3434565));
    PRNG prng1(block(42532335, 334565));

    // The total number that we wish to do
    u64 numOTs = 128;

    KkrtNcoOtSender sender;
    KkrtNcoOtReceiver recv;

    // get up the parameters and get some information back. 
    //  1) false = semi-honest
    //  2) 40  =  statistical security param.
    //  3) numOTs = number of OTs that we will perform
    sender.configure(false, 40, 128);
    recv.configure(false, 40, 128);

    // the number of base OT that need to be done
    u64 baseCount = sender.getBaseOTCount();

    // Fake some base OTs
    std::vector<block> baseRecv(baseCount);
    std::vector<std::array<block, 2>> baseSend(baseCount);
    BitVector baseChoice(baseCount);
    baseChoice.randomize(prng0);
    prng0.get((u8*)baseSend.data()->data(), sizeof(block) * 2 * baseSend.size());
    for (u64 i = 0; i < baseCount; ++i){
        baseRecv[i] = baseSend[i][baseChoice[i]];
    }

    // set up networking
    IOService ios;
    Session ep0(ios, "localhost", 1212, SessionMode::Server);
    Session ep1(ios, "localhost", 1212, SessionMode::Client);
    auto recvChl = ep1.addChannel();
    auto sendChl = ep0.addChannel();


    // set the base OTs
    sender.setBaseOts(baseRecv, baseChoice);
    recv.setBaseOts(baseSend);

    u64 stepSize = 10;
    std::vector<block> inputs(stepSize);

    for (size_t j = 0; j < 2; j++){
        // perform the init on each of the classes. should be performed concurrently
        auto thrd = std::thread([&]() { sender.init(numOTs, prng0, sendChl); });
        recv.init(numOTs, prng1, recvChl);
        thrd.join();

        std::vector<block> encoding1(stepSize), encoding2(stepSize);

        // Get the random OT messages
        for (u64 i = 0; i < numOTs; i += stepSize)
        {

            prng0.get(inputs.data(), inputs.size());

            auto ss = std::min<u64>(stepSize, numOTs - i);
            for (u64 k = 0; k < ss; ++k){
                // The receiver MUST encode before the sender. Here we are only calling encode(...) 
                // for a single i. But the receiver can also encode many i, but should only make one 
                // call to encode for any given value of i.
                recv.encode(i + k, &inputs[k], (u8*)&encoding1[k], sizeof(block));
            }

            // This call will send to the other party the next "stepSize" corrections to the sender.
            // If we had made more or less calls to encode above (for contigious i), then we should replace
            // stepSize with however many calls we made. In an extreme case, the reciever can perform
            // encode for i \in {0, ..., numOTs - 1}  and then call sendCorrection(recvChl, numOTs).
            recv.sendCorrection(recvChl, ss);

            // receive the next stepSize correction values. This allows the sender to now call encode
            // on the next stepSize OTs.
            sender.recvCorrection(sendChl, ss);

            for (u64 k = 0; k < ss; ++k){
                // the sender can now call encode(i, ...) for k \in {0, ..., i}. 
                // Lets encode the same input and then we should expect to
                // get the same encoding.
                sender.encode(i + k, &inputs[k], (u8*)&encoding2[k], sizeof(block));

                // check that we do in fact get the same value
                if (neq(encoding1[k], encoding2[k]))
                    throw UnitTestFail(LOCATION);

                // In addition to the sender being able to obtain the same value as the receiver,
                // the sender can encode and other codeword. This should result in a different 
                // encoding.
                inputs[k] = prng0.get<block>();

                sender.encode(i + k, &inputs[k], (u8*)&encoding2[k], sizeof(block));

                if (eq(encoding1[k], encoding2[k]))
                    throw UnitTestFail(LOCATION);
            }
        }
    }

    // Double check that we can call split and perform the same tests.
    auto recv2Ptr = recv.split();
    auto send2Ptr = sender.split();

    auto& recv2 = *recv2Ptr;
    auto& send2 = *send2Ptr;

    for (size_t j = 0; j < 2; j++){
        auto thrd = std::thread([&]() {
            send2.init(numOTs, prng0, sendChl);
        });

        recv2.init(numOTs, prng1, recvChl);

        thrd.join();


        for (u64 i = 0; i < numOTs; ++i)
        {
            block input = prng0.get<block>();

            block encoding1, encoding2;
            recv2.encode(i, &input, &encoding1);

            recv2.sendCorrection(recvChl, 1);
            send2.recvCorrection(sendChl, 1);

            send2.encode(i, &input, &encoding2);

            if (neq(encoding1, encoding2))
                throw UnitTestFail(LOCATION);

            input = prng0.get<block>();

            send2.encode(i, &input, &encoding2);

            if (eq(encoding1, encoding2))
                throw UnitTestFail(LOCATION);
        }
    }
}

int main(){
    test_KKRT();
    std::cout << "Successfully test KKRT!" << endl;
}