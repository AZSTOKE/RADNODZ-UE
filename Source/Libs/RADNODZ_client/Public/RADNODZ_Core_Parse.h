// Copyright (c) 2026 AZSTOKE Inc. All rights reserved.
// Licensed under the terms in LICENSE.txt (see project root).
// Modification and redistribution are prohibited except as
// permitted therein.

#pragma once
#include "RADNODZ_Core.h"
#include "RpcCall.h"

// Parse helpers (step 3 of the deferred-RPC split): turn RpcCall.resultJson into
// the typed output. Pairs with RADNODZ_Core_Build.h. See RpcCall.h.

namespace RADNODZ_client::Core
{
	/****************** Error *****************************/

	int AZ_GetErrorCode_Parse(const RpcCall& call);

	std::string AZ_GetErrorMsg_Parse(const RpcCall& call);

	std::string AZ_GetErrorMsg_Lang_Parse(const RpcCall& call);

	std::string AZ_GetErrorMsg_Code_Parse(const RpcCall& call);

	std::string AZ_GetErrorMsg_Code_Lang_Parse(const RpcCall& call);


	/****************** License *****************************/

	int AZ_CheckLicense_Parse(TcpClient& tcpClient, const RpcCall& call);
}
