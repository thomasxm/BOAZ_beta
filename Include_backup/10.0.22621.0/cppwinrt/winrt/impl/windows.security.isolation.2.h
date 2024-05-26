// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Security_Isolation_2_H
#define WINRT_Windows_Security_Isolation_2_H
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Security.Isolation.1.h"
WINRT_EXPORT namespace winrt::Windows::Security::Isolation
{
    struct HostMessageReceivedCallback : winrt::Windows::Foundation::IUnknown
    {
        HostMessageReceivedCallback(std::nullptr_t = nullptr) noexcept {}
        HostMessageReceivedCallback(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IUnknown(ptr, take_ownership_from_abi) {}
        template <typename L> HostMessageReceivedCallback(L lambda);
        template <typename F> HostMessageReceivedCallback(F* function);
        template <typename O, typename M> HostMessageReceivedCallback(O* object, M method);
        template <typename O, typename M> HostMessageReceivedCallback(com_ptr<O>&& object, M method);
        template <typename O, typename M> HostMessageReceivedCallback(weak_ref<O>&& object, M method);
        auto operator()(winrt::guid const& receiverId, param::vector_view<winrt::Windows::Foundation::IInspectable> const& message) const;
    };
    struct MessageReceivedCallback : winrt::Windows::Foundation::IUnknown
    {
        MessageReceivedCallback(std::nullptr_t = nullptr) noexcept {}
        MessageReceivedCallback(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IUnknown(ptr, take_ownership_from_abi) {}
        template <typename L> MessageReceivedCallback(L lambda);
        template <typename F> MessageReceivedCallback(F* function);
        template <typename O, typename M> MessageReceivedCallback(O* object, M method);
        template <typename O, typename M> MessageReceivedCallback(com_ptr<O>&& object, M method);
        template <typename O, typename M> MessageReceivedCallback(weak_ref<O>&& object, M method);
        auto operator()(winrt::guid const& receiverId, param::vector_view<winrt::Windows::Foundation::IInspectable> const& message) const;
    };
    struct IsolatedWindowsEnvironmentCreateProgress
    {
        winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentProgressState State;
        uint32_t PercentComplete;
    };
    inline bool operator==(IsolatedWindowsEnvironmentCreateProgress const& left, IsolatedWindowsEnvironmentCreateProgress const& right) noexcept
    {
        return left.State == right.State && left.PercentComplete == right.PercentComplete;
    }
    inline bool operator!=(IsolatedWindowsEnvironmentCreateProgress const& left, IsolatedWindowsEnvironmentCreateProgress const& right) noexcept
    {
        return !(left == right);
    }
    struct __declspec(empty_bases) IsolatedWindowsEnvironment : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment,
        impl::require<IsolatedWindowsEnvironment, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment2, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment3, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment4>
    {
        IsolatedWindowsEnvironment(std::nullptr_t) noexcept {}
        IsolatedWindowsEnvironment(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironment(ptr, take_ownership_from_abi) {}
        static auto CreateAsync(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOptions const& options);
        static auto CreateAsync(winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOptions const& options, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentTelemetryParameters const& telemetryParameters);
        static auto GetById(param::hstring const& environmentId);
        static auto FindByOwnerId(param::hstring const& environmentOwnerId);
    };
    struct __declspec(empty_bases) IsolatedWindowsEnvironmentCreateResult : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentCreateResult,
        impl::require<IsolatedWindowsEnvironmentCreateResult, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentCreateResult2>
    {
        IsolatedWindowsEnvironmentCreateResult(std::nullptr_t) noexcept {}
        IsolatedWindowsEnvironmentCreateResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentCreateResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IsolatedWindowsEnvironmentFile : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFile,
        impl::require<IsolatedWindowsEnvironmentFile, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFile2>
    {
        IsolatedWindowsEnvironmentFile(std::nullptr_t) noexcept {}
        IsolatedWindowsEnvironmentFile(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentFile(ptr, take_ownership_from_abi) {}
    };
    struct IsolatedWindowsEnvironmentHost
    {
        IsolatedWindowsEnvironmentHost() = delete;
        [[nodiscard]] static auto IsReady();
        [[nodiscard]] static auto HostErrors();
    };
    struct __declspec(empty_bases) IsolatedWindowsEnvironmentLaunchFileResult : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentLaunchFileResult
    {
        IsolatedWindowsEnvironmentLaunchFileResult(std::nullptr_t) noexcept {}
        IsolatedWindowsEnvironmentLaunchFileResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentLaunchFileResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IsolatedWindowsEnvironmentOptions : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions,
        impl::require<IsolatedWindowsEnvironmentOptions, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions2, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions3>
    {
        IsolatedWindowsEnvironmentOptions(std::nullptr_t) noexcept {}
        IsolatedWindowsEnvironmentOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOptions(ptr, take_ownership_from_abi) {}
        IsolatedWindowsEnvironmentOptions();
    };
    struct IsolatedWindowsEnvironmentOwnerRegistration
    {
        IsolatedWindowsEnvironmentOwnerRegistration() = delete;
        static auto Register(param::hstring const& ownerName, winrt::Windows::Security::Isolation::IsolatedWindowsEnvironmentOwnerRegistrationData const& ownerRegistrationData);
        static auto Unregister(param::hstring const& ownerName);
    };
    struct __declspec(empty_bases) IsolatedWindowsEnvironmentOwnerRegistrationData : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationData
    {
        IsolatedWindowsEnvironmentOwnerRegistrationData(std::nullptr_t) noexcept {}
        IsolatedWindowsEnvironmentOwnerRegistrationData(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationData(ptr, take_ownership_from_abi) {}
        IsolatedWindowsEnvironmentOwnerRegistrationData();
    };
    struct __declspec(empty_bases) IsolatedWindowsEnvironmentOwnerRegistrationResult : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationResult
    {
        IsolatedWindowsEnvironmentOwnerRegistrationResult(std::nullptr_t) noexcept {}
        IsolatedWindowsEnvironmentOwnerRegistrationResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentOwnerRegistrationResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IsolatedWindowsEnvironmentPostMessageResult : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentPostMessageResult
    {
        IsolatedWindowsEnvironmentPostMessageResult(std::nullptr_t) noexcept {}
        IsolatedWindowsEnvironmentPostMessageResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentPostMessageResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IsolatedWindowsEnvironmentProcess : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentProcess
    {
        IsolatedWindowsEnvironmentProcess(std::nullptr_t) noexcept {}
        IsolatedWindowsEnvironmentProcess(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentProcess(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IsolatedWindowsEnvironmentShareFileRequestOptions : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFileRequestOptions
    {
        IsolatedWindowsEnvironmentShareFileRequestOptions(std::nullptr_t) noexcept {}
        IsolatedWindowsEnvironmentShareFileRequestOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFileRequestOptions(ptr, take_ownership_from_abi) {}
        IsolatedWindowsEnvironmentShareFileRequestOptions();
    };
    struct __declspec(empty_bases) IsolatedWindowsEnvironmentShareFileResult : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFileResult
    {
        IsolatedWindowsEnvironmentShareFileResult(std::nullptr_t) noexcept {}
        IsolatedWindowsEnvironmentShareFileResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFileResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IsolatedWindowsEnvironmentShareFolderRequestOptions : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFolderRequestOptions
    {
        IsolatedWindowsEnvironmentShareFolderRequestOptions(std::nullptr_t) noexcept {}
        IsolatedWindowsEnvironmentShareFolderRequestOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFolderRequestOptions(ptr, take_ownership_from_abi) {}
        IsolatedWindowsEnvironmentShareFolderRequestOptions();
    };
    struct __declspec(empty_bases) IsolatedWindowsEnvironmentShareFolderResult : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFolderResult
    {
        IsolatedWindowsEnvironmentShareFolderResult(std::nullptr_t) noexcept {}
        IsolatedWindowsEnvironmentShareFolderResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentShareFolderResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IsolatedWindowsEnvironmentStartProcessResult : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentStartProcessResult
    {
        IsolatedWindowsEnvironmentStartProcessResult(std::nullptr_t) noexcept {}
        IsolatedWindowsEnvironmentStartProcessResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentStartProcessResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IsolatedWindowsEnvironmentTelemetryParameters : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentTelemetryParameters
    {
        IsolatedWindowsEnvironmentTelemetryParameters(std::nullptr_t) noexcept {}
        IsolatedWindowsEnvironmentTelemetryParameters(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentTelemetryParameters(ptr, take_ownership_from_abi) {}
        IsolatedWindowsEnvironmentTelemetryParameters();
    };
    struct __declspec(empty_bases) IsolatedWindowsEnvironmentUserInfo : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentUserInfo,
        impl::require<IsolatedWindowsEnvironmentUserInfo, winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentUserInfo2>
    {
        IsolatedWindowsEnvironmentUserInfo(std::nullptr_t) noexcept {}
        IsolatedWindowsEnvironmentUserInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Security::Isolation::IIsolatedWindowsEnvironmentUserInfo(ptr, take_ownership_from_abi) {}
    };
    struct IsolatedWindowsHostMessenger
    {
        IsolatedWindowsHostMessenger() = delete;
        static auto PostMessageToReceiver(winrt::guid const& receiverId, param::vector_view<winrt::Windows::Foundation::IInspectable> const& message);
        static auto GetFileId(param::hstring const& filePath);
        static auto RegisterHostMessageReceiver(winrt::guid const& receiverId, winrt::Windows::Security::Isolation::HostMessageReceivedCallback const& hostMessageReceivedCallback);
        static auto UnregisterHostMessageReceiver(winrt::guid const& receiverId);
    };
}
#endif
