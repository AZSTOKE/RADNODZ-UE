// Copyright (c) 2026 AZSTOKE Inc. All rights reserved.
// Licensed under the terms in LICENSE.md (see project root).
// Modification and redistribution are prohibited except as
// permitted therein.

#pragma once
#include <memory>
#include <string>
#include <cstdint>
#include <functional>
#include <vector>

namespace RADNODZ_client
{
    // State of the server host key seen at connect time.
    // A pinned key that matches does NOT invoke the verifier.
    enum class HostKeyStatus
    {
        Unknown,   // first seen (TOFU): no pin recorded for this serverId
        Changed,   // known but mismatched (server reinstall OR attack)
    };

    // Verifier decision.
    enum class HostKeyVerdict
    {
        Reject,        // refuse the connection
        AcceptAndPin,  // accept and pin for future automatic verification
    };

    // Information passed to the host key verifier callback.
    struct HostKeyInfo
    {
        std::string   serverId;      // app-supplied logical server id (= pin key)
        std::string   ip;
        int           port = 0;
        std::string   fingerprint;   // "SHA256:<base64>"
        std::string   publicKeyPem;
        HostKeyStatus status = HostKeyStatus::Unknown;
    };

    // A pinned server entry, keyed by the app-supplied logical server id.
    struct PinnedServer
    {
        std::string serverId;
        std::string fingerprint;   // "SHA256:<base64>"
        std::string publicKeyPem;
    };

    // Called when the server host key needs a decision (Unknown/Changed).
    // Registration is mandatory (fail-close): connecting without a verifier set,
    // when a decision is required, refuses the connection.
    using HostKeyVerifier = std::function<HostKeyVerdict(const HostKeyInfo&)>;

    class TcpClient
    {
    private:
        struct Impl;
        std::unique_ptr<Impl> impl_;

		std::string ip_;
		int port_;

		int64_t lastSendTime_ = 0; 
		int64_t lastServerRecvTime_ = 0; 
		int64_t lastServerReturnTime_ = 0;
		int64_t lastRecvTime_ = 0;

    public:
        TcpClient();
        ~TcpClient();

        TcpClient(const std::string& ip, const int port);

        bool Connect();

        bool Connect(const std::string& ip, const int port);

        // ===== Secure comms: identity (for mTLS) =====
        // The consuming app injects the storage directory for the key/cert
        // (handles UE/Android/Mac sandboxes). Call before GenerateIdentity/Connect.
        void SetStorageDirectory(const std::string& dir);

        // Prepare an ECDSA P-256 key pair + self-signed cert (idempotent:
        // load if present, generate if absent). Fails if the storage dir is unset.
        bool GenerateIdentity();

        // Explicit rotation (always generate anew). Invalidates all existing pairings.
        bool RegenerateIdentity();

        // For pairing: own public key PEM (register this in the server's authorized set).
        std::string GetOwnPublicKeyPem();

        // Own fingerprint, "SHA256:<base64>".
        std::string GetOwnFingerprint();

        // ===== Secure comms: server verification / pinning =====
        // Logical server id used as the pin key (IP may change on a LAN).
        // Call before Connect.
        void SetServerId(const std::string& id);

        // Register the host key verifier (mandatory for a first/changed key: fail-close).
        void SetHostKeyVerifier(HostKeyVerifier v);

        // Pin management (trust reset).
        std::vector<PinnedServer> ListPinnedServers();
        bool RemovePinnedServer(const std::string& serverId);

        std::string Send(const std::string& message);

        void Disconnect();

        bool IsConnected() const;

        int64_t GetLastSendTime() const;
        int64_t GetLastServerRecvTime() const;
        int64_t GetLastServerReturnTime() const;
        int64_t GetLastRecvTime() const;

        int errorCode = 0;

        std::string errorMessage = "";

        std::string errorDetails = "";
    };
}
