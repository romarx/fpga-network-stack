/*
 * Copyright (c) 2019, Systems Group, ETH Zurich
 * Copyright (c) 2016, Xilinx, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "mac_ip_encode_config.hpp"
#include "mac_ip_encode.hpp"
#include "../ethernet/ethernet.hpp"
#include "../ipv4/ipv4.hpp"

template <int WIDTH>
void extract_ip_address(hls::stream<net_axis<WIDTH> >&		dataIn,
						hls::stream<net_axis<WIDTH> >&		dataOut)
						

{
	#pragma HLS PIPELINE II=1
	#pragma HLS INLINE off

	static ipv4Header<WIDTH> header;


	if (!dataIn.empty())
	{
		net_axis<WIDTH> currWord = dataIn.read();
		header.parseWord(currWord.data);
		dataOut.write(currWord);
		
		if (currWord.last)
		{
			header.clear();
		}
	
	}
}

template <int WIDTH>
void insert_ip_checksum(hls::stream<net_axis<WIDTH> >&		dataIn,
						hls::stream<ap_uint<16> >&	checksumFifoIn,
						hls::stream<net_axis<WIDTH> >&		dataOut)
{
	#pragma HLS PIPELINE II=1
	#pragma HLS INLINE off

	static ap_uint<4> wordCount = 0;
	static ap_uint<16> checksum;

	switch (wordCount)
	{
	case 0:
		if (!dataIn.empty() && !checksumFifoIn.empty())
		{
			net_axis<WIDTH> currWord = dataIn.read();
			checksumFifoIn.read(checksum);
         if (WIDTH > 64)
         {
			   currWord.data(95, 80) = reverse(checksum);
         }

			dataOut.write(currWord);
			wordCount++;
			if (currWord.last)
			{
				wordCount = 0;
			}
		}
		break;
	case 1:
		if (!dataIn.empty())
		{
			net_axis<WIDTH> currWord = dataIn.read();
         if (WIDTH == 64)
         {
			   currWord.data(31, 16) = reverse(checksum);
         }

			dataOut.write(currWord);
			wordCount++;
			if (currWord.last)
			{
				wordCount = 0;
			}
		}
		break;
	default:
		if (!dataIn.empty())
		{
			net_axis<WIDTH> currWord = dataIn.read();
			dataOut.write(currWord);
			if (currWord.last)
			{
				wordCount = 0;
			}
		}
		break;
	}
}

template <int WIDTH>
void create_ethernet_header (hls::stream<net_axis<WIDTH> >&	dataIn,
						hls::stream<ethHeader<WIDTH> >&	headerOut,
						hls::stream<net_axis<WIDTH> >&	dataOut,
						ap_uint<48>					myMacAddress,
						ap_uint<48>					theirMacAddress)

{
	#pragma HLS PIPELINE II=1
	#pragma HLS INLINE off

	enum fsmStateType {HDR, FWD};
	static fsmStateType hdr_state = HDR;

	switch (hdr_state)
	{
	case HDR:
		if (!dataIn.empty()){
			
			net_axis<WIDTH> word = dataIn.read();

			//Construct Header
			ethHeader<WIDTH> header;
			header.clear();
			header.setDstAddress(theirMacAddress);
			header.setSrcAddress(myMacAddress);
			header.setEthertype(0x0800);
			
			headerOut.write(header);
			dataOut.write(word);

			if (!word.last)
			{
				hdr_state = FWD;
			}
		}
		break;
	case FWD:
		if (!dataIn.empty())
		{
			net_axis<WIDTH> word = dataIn.read();
			dataOut.write(word);
			if (word.last)
			{
				hdr_state = HDR;
			}
		}
		break;
	}
}

template <int WIDTH>
void insert_ethernet_header(hls::stream<ethHeader<WIDTH> >&		headerIn,
							hls::stream<net_axis<WIDTH> >&		dataIn,
							hls::stream<net_axis<WIDTH> >&		dataOut)
{
	#pragma HLS PIPELINE II=1
	#pragma HLS INLINE off

	enum fsmStateType {HEADER, PARTIAL_HEADER, BODY};
	static fsmStateType ge_state = (ETH_HEADER_SIZE >= WIDTH) ? HEADER : PARTIAL_HEADER;
	static ethHeader<WIDTH> header;

	switch (ge_state)
	{
	case HEADER:
	{
		if (!headerIn.empty()) // This works because for 64bit there is only one full header word 
		{
			headerIn.read(header);
			net_axis<WIDTH> currWord;
			//Always holds, no check required
			header.consumeWord(currWord.data);
			ge_state = PARTIAL_HEADER;
			currWord.keep = ~0;
			currWord.last = 0;
			dataOut.write(currWord);
		}
		break;
	}
	case PARTIAL_HEADER:
		if ((!headerIn.empty() || (ETH_HEADER_SIZE >= WIDTH)) && !dataIn.empty())
		{
			if (ETH_HEADER_SIZE < WIDTH)
			{
				headerIn.read(header);
			}
			net_axis<WIDTH> currWord = dataIn.read();
			header.consumeWord(currWord.data);
			dataOut.write(currWord);

			if (!currWord.last)
			{
				ge_state = BODY;
			}
			else
			{
				ge_state = (ETH_HEADER_SIZE >= WIDTH) ? HEADER : PARTIAL_HEADER;
			}
		}
		break;
	case BODY:
		if (!dataIn.empty())
		{
			net_axis<WIDTH> currWord = dataIn.read();
			dataOut.write(currWord);
			if (currWord.last)
			{
				ge_state = (ETH_HEADER_SIZE >= WIDTH) ? HEADER : PARTIAL_HEADER;
			}
		}
		break;
	} //switch

}

template <int WIDTH>
void mac_ip_encode( hls::stream<net_axis<WIDTH> >&			dataIn,
					hls::stream<net_axis<WIDTH> >&			dataOut,
					ap_uint<48>					myMacAddress,
					ap_uint<48>					theirMacAddress)
{
	#pragma HLS INLINE

	// FIFOs
	static hls::stream<net_axis<WIDTH> > dataStreamBuffer0("dataStreamBuffer0");
	static hls::stream<net_axis<WIDTH> > dataStreamBuffer1("dataStreamBuffer1");
	static hls::stream<net_axis<WIDTH> > dataStreamBuffer2("dataStreamBuffer2");
	static hls::stream<net_axis<WIDTH> > dataStreamBuffer3("dataStreamBuffer3");
	static hls::stream<net_axis<WIDTH> > dataStreamBuffer4("dataStreamBuffer4");

	#pragma HLS stream variable=dataStreamBuffer0 depth=2
	#pragma HLS stream variable=dataStreamBuffer1 depth=32
	#pragma HLS stream variable=dataStreamBuffer2 depth=2
	#pragma HLS stream variable=dataStreamBuffer3 depth=2
	#pragma HLS stream variable=dataStreamBuffer4 depth=2
#if defined( __VITIS_HLS__)
	#pragma HLS aggregate  variable=dataStreamBuffer0 compact=bit
	#pragma HLS aggregate  variable=dataStreamBuffer1 compact=bit
	#pragma HLS aggregate  variable=dataStreamBuffer2 compact=bit
	#pragma HLS aggregate  variable=dataStreamBuffer3 compact=bit
	#pragma HLS aggregate  variable=dataStreamBuffer4 compact=bit
#else
	#pragma HLS DATA_PACK variable=dataStreamBuffer0
	#pragma HLS DATA_PACK variable=dataStreamBuffer1
	#pragma HLS DATA_PACK variable=dataStreamBuffer2
	#pragma HLS DATA_PACK variable=dataStreamBuffer3
	#pragma HLS DATA_PACK variable=dataStreamBuffer4
#endif

	static hls::stream<subSums<WIDTH/16> >	subSumFifo("subSumFifo");
	static hls::stream<ap_uint<16> >		checksumFifo("checksumFifo");
	static hls::stream<ethHeader<WIDTH> >	headerFifo("headerFifo");
	#pragma HLS stream variable=subSumFifo depth=2
	#pragma HLS stream variable=checksumFifo depth=16
	#pragma HLS stream variable=headerFifo depth=2
#if defined( __VITIS_HLS__)
	#pragma HLS aggregate  variable=headerFifo compact=bit

	//extract_ip_address(dataIn, dataStreamBuffer0);

	mac_compute_ipv4_checksum(dataIn, dataStreamBuffer1, subSumFifo, true);
	mac_finalize_ipv4_checksum<WIDTH/16>(subSumFifo, checksumFifo);

	insert_ip_checksum(dataStreamBuffer1, checksumFifo, dataStreamBuffer2);

	create_ethernet_header(dataStreamBuffer2, headerFifo, dataStreamBuffer3, myMacAddress, theirMacAddress);
	mac_lshiftWordByOctet<WIDTH, 1>(((ETH_HEADER_SIZE%WIDTH)/8), dataStreamBuffer3, dataStreamBuffer4);
	insert_ethernet_header(headerFifo, dataStreamBuffer4, dataOut);
#else
	#pragma HLS DATA_PACK variable=headerFifo
	//extract_ip_address(dataIn, dataStreamBuffer0);
	
	compute_ipv4_checksum(dataIn, dataStreamBuffer1, subSumFifo, true);
	finalize_ipv4_checksum<WIDTH/16>(subSumFifo, checksumFifo);

	insert_ip_checksum(dataStreamBuffer1, checksumFifo, dataStreamBuffer2);

	create_ethernet_header(arpTableIn, dataStreamBuffer2, headerFifo, dataStreamBuffer3, myMacAddress, theirMacAddress);
	lshiftWordByOctet<WIDTH, 1>(((ETH_HEADER_SIZE%WIDTH)/8), dataStreamBuffer3, dataStreamBuffer4);
	insert_ethernet_header(headerFifo, dataStreamBuffer4, dataOut);
#endif
	
}

#if defined( __VITIS_HLS__)
void mac_ip_encode_top( hls::stream<ap_axiu<DATA_WIDTH, 0, 0, 0> >&			dataIn,
					hls::stream<ap_axiu<DATA_WIDTH, 0, 0, 0> >&			dataOut,
					ap_uint<48>					myMacAddress,
					ap_uint<48>					theirMacAddress)
{
	#pragma HLS DATAFLOW disable_start_propagation
	#pragma HLS INTERFACE ap_ctrl_none port=return

	#pragma HLS INTERFACE axis register port=dataIn name=s_axis_ip
	#pragma HLS INTERFACE axis register port=dataOut name=m_axis_ip

	#pragma HLS INTERFACE ap_none register port=theirMacAddress
	#pragma HLS INTERFACE ap_none register port=myMacAddress


	static hls::stream<net_axis<DATA_WIDTH> > dataIn_internal;
	#pragma HLS STREAM depth=2 variable=dataIn_internal
	static hls::stream<net_axis<DATA_WIDTH> > dataOut_internal;
	#pragma HLS STREAM depth=2 variable=dataOut_internal

	convert_axis_to_net_axis<DATA_WIDTH>(dataIn, 
							dataIn_internal);

	convert_net_axis_to_axis<DATA_WIDTH>(dataOut_internal, 
							dataOut);

   	mac_ip_encode<DATA_WIDTH>( dataIn_internal,
                              dataOut_internal,
                              myMacAddress,
							  theirMacAddress);
#else
void mac_ip_encode_top( hls::stream<net_axis<DATA_WIDTH> >&			dataIn,
					hls::stream<net_axis<DATA_WIDTH> >&			dataOut,
					ap_uint<48>					myMacAddress,
					ap_uint<48>					theirMacAddress)
{
	#pragma HLS DATAFLOW disable_start_propagation
	#pragma HLS INTERFACE ap_ctrl_none port=return

	#pragma HLS INTERFACE axis register port=dataIn name=s_axis_ip
	#pragma HLS INTERFACE axis register port=dataOut name=m_axis_ip


	#pragma HLS INTERFACE ap_stable register port=theirMacAddress
	#pragma HLS INTERFACE ap_stable register port=myMacAddress


   mac_ip_encode<DATA_WIDTH>( dataIn,
                              dataOut,
                              myMacAddress,
							  theirMacAddress);
#endif
}
