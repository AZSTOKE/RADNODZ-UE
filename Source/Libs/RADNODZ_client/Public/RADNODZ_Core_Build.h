// Copyright (c) 2026 AZSTOKE Inc. All rights reserved.
// Licensed under the terms in LICENSE.txt (see project root).
// Modification and redistribution are prohibited except as
// permitted therein.

#pragma once
#include "RADNODZ_Core.h"
#include "RpcCall.h"

namespace RADNODZ_client::Core
{
	/****************** Error *****************************/

	RpcCall AZ_GetErrorCode_Build();

	RpcCall AZ_GetErrorMsg_Build();

	RpcCall AZ_GetErrorMsg_Lang_Build(std::string lang);

	RpcCall AZ_GetErrorMsg_Code_Build(int code);

	RpcCall AZ_GetErrorMsg_Code_Lang_Build(int code, std::string lang);


	/****************** License *****************************/

	RpcCall AZ_CheckLicense_Build();
}
