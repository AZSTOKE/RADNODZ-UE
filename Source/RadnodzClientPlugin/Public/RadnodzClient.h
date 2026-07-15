// Copyright (c) 2026 AZSTOKE Inc. All rights reserved.
// Licensed under the terms in LICENSE.md (see project root).
// Modification and redistribution are prohibited except as
// permitted therein.

#pragma once
#include "CoreMinimal.h"
#include "UObject/Object.h"
#include "RadnodzCommonClass.h"
#include "TcpClient.h"
#include "Engine/DataAsset.h"
#include "RadnodzClient.generated.h"

USTRUCT(BlueprintType)
struct RADNODZCLIENTPLUGIN_API FRigdocksError
{
public:

	GENERATED_BODY()

	UPROPERTY(EditAnywhere, BlueprintReadOnly, Category = "RADNODZ|Error")
	int ErrorCode{};

	UPROPERTY(EditAnywhere, BlueprintReadOnly, Category = "RADNODZ|Error")
	FString Message;

	UPROPERTY(EditAnywhere, BlueprintReadOnly, Category = "RADNODZ|Error")
	FString Details;

};

// 認可済みサーバ(ピン留め)1件。
USTRUCT(BlueprintType)
struct RADNODZCLIENTPLUGIN_API FRadnodzPinnedServer
{
	GENERATED_BODY()

	UPROPERTY(BlueprintReadOnly, Category = "RADNODZ|Security")
	FString ServerId;

	UPROPERTY(BlueprintReadOnly, Category = "RADNODZ|Security")
	FString Fingerprint;

	UPROPERTY(BlueprintReadOnly, Category = "RADNODZ|Security")
	FString PublicKeyPem;
};

UCLASS(BlueprintType)
class RADNODZCLIENTPLUGIN_API URadnodzClient : public URadnodzCommonClass
{
public:

	GENERATED_BODY()

	UFUNCTION(BlueprintCallable, Category = "RADNODZ|Client")
	static URadnodzClient* CreateRadnodzClient();

	UFUNCTION(BlueprintCallable, Category = "RADNODZ|Client")
	bool Connect(const FString& ip, int port);

	UFUNCTION(BlueprintCallable, Category = "RADNODZ|Client")
	FString Send(const FString& message);

	UFUNCTION(BlueprintCallable, Category = "RADNODZ|Client")
	void Disconnect();

	UFUNCTION(BlueprintPure, Category = "RADNODZ|Client")
	bool IsConnected() const;
	UFUNCTION(BlueprintCallable, Category = "RADNODZ|Client")
	FRigdocksError GetError();
	/** 直近の Send() でクライアントが APIDock へコマンドを送信した時刻。 */
	UFUNCTION(BlueprintPure, Category = "RADNODZ|Client")
	int64 GetLastSendTime() const;

	/** 直近の Send() で APIDock が処理を受け取った時刻(サーバから受領)。 */
	UFUNCTION(BlueprintPure, Category = "RADNODZ|Client")
	int64 GetLastServerRecvTime() const;

	/** 直近の Send() で APIDock が処理を返した時刻(サーバから受領)。 */
	UFUNCTION(BlueprintPure, Category = "RADNODZ|Client")
	int64 GetLastServerReturnTime() const;

	/** 直近の Send() でクライアントが結果を受け取り終えた時刻。 */
	UFUNCTION(BlueprintPure, Category = "RADNODZ|Client")
	int64 GetLastRecvTime() const;

	UFUNCTION(BlueprintPure, Category = "RADNODZ|Client")
	static int64 GetNowUnixMicros();

	UFUNCTION(BlueprintCallable, Category = "RADNODZ|Client")
	bool SendTimingProbe();
	RADNODZ_client::TcpClient& GetClient();

	// ===== セキュア通信: アイデンティティ(mTLS) =====
	/** 鍵/証明書の保存先を指定する(GenerateIdentity/Connect より前に呼ぶ)。 */
	UFUNCTION(BlueprintCallable, Category = "RADNODZ|Security")
	void SetStorageDirectory(const FString& Dir);

	/** ECDSA P-256 鍵ペア+自己署名証明書を用意する(冪等: 無ければ生成、あればロード)。 */
	UFUNCTION(BlueprintCallable, Category = "RADNODZ|Security")
	bool GenerateIdentity();

	/** 明示的なローテーション(常に新規生成)。既存の全ペアリングは無効化される。 */
	UFUNCTION(BlueprintCallable, Category = "RADNODZ|Security")
	bool RegenerateIdentity();

	/** ペアリング用: 自身の公開鍵 PEM(サーバの authorized に登録する)。 */
	UFUNCTION(BlueprintPure, Category = "RADNODZ|Security")
	FString GetOwnPublicKeyPem();

	/** 自身のフィンガープリント "SHA256:<base64>"。 */
	UFUNCTION(BlueprintPure, Category = "RADNODZ|Security")
	FString GetOwnFingerprint();

	// ===== セキュア通信: サーバ検証(ポリシー方式) =====
	/** ピン留めキーとなる論理サーバ ID(LAN で IP が変わっても同一サーバと識別)。Connect より前に。 */
	UFUNCTION(BlueprintCallable, Category = "RADNODZ|Security")
	void SetServerId(const FString& Id);

	/** 期待するサーバのフィンガープリント。設定するとその値に一致した場合のみ接続を許可(ピン留め)する。 */
	UFUNCTION(BlueprintCallable, Category = "RADNODZ|Security")
	void SetExpectedServerFingerprint(const FString& Fingerprint);

	/** 初回接続時(未ピンのサーバ)を無条件に信頼してピン留めするか(TOFU)。既定 false。 */
	UFUNCTION(BlueprintCallable, Category = "RADNODZ|Security")
	void SetTrustOnFirstUse(bool bEnable);

	// ===== セキュア通信: ピン管理 =====
	/** ピン留め済みサーバの一覧。 */
	UFUNCTION(BlueprintCallable, Category = "RADNODZ|Security")
	TArray<FRadnodzPinnedServer> ListPinnedServers();

	/** 指定した論理サーバ ID のピンを削除する(信頼リセット)。 */
	UFUNCTION(BlueprintCallable, Category = "RADNODZ|Security")
	bool RemovePinnedServer(const FString& ServerId);

private:
	// ポリシーに基づく検証コールバックを client に設定する。
	void EnsureVerifier();

	RADNODZ_client::TcpClient client;

	// サーバ検証ポリシー
	FString ExpectedServerFingerprint;
	bool bTrustOnFirstUse = false;
};