// Copyright (c) 2026 AZSTOKE Inc. All rights reserved.
// Licensed under the terms in LICENSE.md (see project root).
// Modification and redistribution are prohibited except as
// permitted therein.

#include "RadnodzClient.h"
#include "RADNODZ_Core.h"
#include <chrono>

URadnodzClient* URadnodzClient::CreateRadnodzClient()
{
	return NewObject<URadnodzClient>();
}

bool URadnodzClient::Connect(const FString& ip, int port)
{
	return client.Connect(TCHAR_TO_UTF8(*ip), port);
}

FString URadnodzClient::Send(const FString& message)
{
	FString result = UTF8_TO_TCHAR(client.Send(TCHAR_TO_UTF8(*message)).c_str());

	return result;
}

void URadnodzClient::Disconnect()
{
	client.Disconnect();
}

bool URadnodzClient::IsConnected() const
{
	return client.IsConnected();
}

RADNODZ_client::TcpClient& URadnodzClient::GetClient()
{
	 return client; 
}

FRigdocksError URadnodzClient::GetError()
{
	FRigdocksError error;
	error.ErrorCode = client.errorCode;
	error.Message = UTF8_TO_TCHAR(client.errorMessage.c_str());
	error.Details = UTF8_TO_TCHAR(client.errorDetails.c_str());

	return error;
}

int64 URadnodzClient::GetLastSendTime() const
{
	return static_cast<int64>(client.GetLastSendTime());
}

int64 URadnodzClient::GetLastServerRecvTime() const
{
	return static_cast<int64>(client.GetLastServerRecvTime());
}

int64 URadnodzClient::GetLastServerReturnTime() const
{
	return static_cast<int64>(client.GetLastServerReturnTime());
}

int64 URadnodzClient::GetLastRecvTime() const
{
	return static_cast<int64>(client.GetLastRecvTime());
}

int64 URadnodzClient::GetNowUnixMicros()
{
	// Connecter(TcpClient)の時刻計測と同一の system_clock・同一単位(マイクロ秒)を用いる。
	return static_cast<int64>(
		std::chrono::duration_cast<std::chrono::microseconds>(
			std::chrono::system_clock::now().time_since_epoch()).count());
}

bool URadnodzClient::SendTimingProbe()
{
	if (!client.IsConnected())
	{
		return false;
	}

	return RADNODZ_client::Core::AZ_CheckLicense(client) == 0;
}

// ===== セキュア通信: アイデンティティ(mTLS) =====

void URadnodzClient::SetStorageDirectory(const FString& Dir)
{
	client.SetStorageDirectory(TCHAR_TO_UTF8(*Dir));
}

bool URadnodzClient::GenerateIdentity()
{
	return client.GenerateIdentity();
}

bool URadnodzClient::RegenerateIdentity()
{
	return client.RegenerateIdentity();
}

FString URadnodzClient::GetOwnPublicKeyPem()
{
	return UTF8_TO_TCHAR(client.GetOwnPublicKeyPem().c_str());
}

FString URadnodzClient::GetOwnFingerprint()
{
	return UTF8_TO_TCHAR(client.GetOwnFingerprint().c_str());
}

// ===== セキュア通信: サーバ検証(ポリシー方式) =====

void URadnodzClient::SetServerId(const FString& Id)
{
	client.SetServerId(TCHAR_TO_UTF8(*Id));
}

void URadnodzClient::SetExpectedServerFingerprint(const FString& Fingerprint)
{
	ExpectedServerFingerprint = Fingerprint;
	EnsureVerifier();
}

void URadnodzClient::SetTrustOnFirstUse(bool bEnable)
{
	bTrustOnFirstUse = bEnable;
	EnsureVerifier();
}

void URadnodzClient::EnsureVerifier()
{
	// ポリシー方式のサーバ検証:
	//  - 期待 FP が設定されていれば、その値に一致した場合のみ許可(ピン留め)。
	//  - 未設定でも TOFU が有効なら、初回(未ピン)のみ許可。
	//  - それ以外は拒否(フェイルクローズ)。
	client.SetHostKeyVerifier(
		[this](const RADNODZ_client::HostKeyInfo& info) -> RADNODZ_client::HostKeyVerdict
		{
			if (!ExpectedServerFingerprint.IsEmpty())
			{
				const std::string expected = TCHAR_TO_UTF8(*ExpectedServerFingerprint);
				return (info.fingerprint == expected)
					? RADNODZ_client::HostKeyVerdict::AcceptAndPin
					: RADNODZ_client::HostKeyVerdict::Reject;
			}

			if (bTrustOnFirstUse && info.status == RADNODZ_client::HostKeyStatus::Unknown)
			{
				return RADNODZ_client::HostKeyVerdict::AcceptAndPin;
			}

			return RADNODZ_client::HostKeyVerdict::Reject;
		});
}

// ===== セキュア通信: ピン管理 =====

TArray<FRadnodzPinnedServer> URadnodzClient::ListPinnedServers()
{
	TArray<FRadnodzPinnedServer> Out;
	for (const auto& p : client.ListPinnedServers())
	{
		FRadnodzPinnedServer e;
		e.ServerId = UTF8_TO_TCHAR(p.serverId.c_str());
		e.Fingerprint = UTF8_TO_TCHAR(p.fingerprint.c_str());
		e.PublicKeyPem = UTF8_TO_TCHAR(p.publicKeyPem.c_str());
		Out.Add(e);
	}
	return Out;
}

bool URadnodzClient::RemovePinnedServer(const FString& ServerId)
{
	return client.RemovePinnedServer(TCHAR_TO_UTF8(*ServerId));
}

