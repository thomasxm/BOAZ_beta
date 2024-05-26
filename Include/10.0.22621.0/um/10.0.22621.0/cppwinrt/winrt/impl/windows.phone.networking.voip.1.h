// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Phone_Networking_Voip_1_H
#define WINRT_Windows_Phone_Networking_Voip_1_H
#include "winrt/impl/Windows.Phone.Networking.Voip.0.h"
WINRT_EXPORT namespace winrt::Windows::Phone::Networking::Voip
{
    struct __declspec(empty_bases) ICallAnswerEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICallAnswerEventArgs>
    {
        ICallAnswerEventArgs(std::nullptr_t = nullptr) noexcept {}
        ICallAnswerEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICallRejectEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICallRejectEventArgs>
    {
        ICallRejectEventArgs(std::nullptr_t = nullptr) noexcept {}
        ICallRejectEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ICallStateChangeEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ICallStateChangeEventArgs>
    {
        ICallStateChangeEventArgs(std::nullptr_t = nullptr) noexcept {}
        ICallStateChangeEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMuteChangeEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMuteChangeEventArgs>
    {
        IMuteChangeEventArgs(std::nullptr_t = nullptr) noexcept {}
        IMuteChangeEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IQuerySeamlessUpgradeSupportOperation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IQuerySeamlessUpgradeSupportOperation>,
        impl::require<winrt::Windows::Phone::Networking::Voip::IQuerySeamlessUpgradeSupportOperation, winrt::Windows::Phone::Networking::Voip::IVoipOperation>
    {
        IQuerySeamlessUpgradeSupportOperation(std::nullptr_t = nullptr) noexcept {}
        IQuerySeamlessUpgradeSupportOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVoipCallCoordinator :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVoipCallCoordinator>
    {
        IVoipCallCoordinator(std::nullptr_t = nullptr) noexcept {}
        IVoipCallCoordinator(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVoipCallCoordinator2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVoipCallCoordinator2>,
        impl::require<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator2, winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator>
    {
        IVoipCallCoordinator2(std::nullptr_t = nullptr) noexcept {}
        IVoipCallCoordinator2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVoipCallCoordinator3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVoipCallCoordinator3>,
        impl::require<winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator3, winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator>
    {
        IVoipCallCoordinator3(std::nullptr_t = nullptr) noexcept {}
        IVoipCallCoordinator3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
        using impl::consume_t<IVoipCallCoordinator3, IVoipCallCoordinator3>::RequestNewIncomingCall;
        using impl::consume_t<IVoipCallCoordinator3, winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator>::RequestNewIncomingCall;
    };
    struct __declspec(empty_bases) IVoipCallCoordinatorStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVoipCallCoordinatorStatics>
    {
        IVoipCallCoordinatorStatics(std::nullptr_t = nullptr) noexcept {}
        IVoipCallCoordinatorStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVoipCallCoordinatorWithAppDeterminedUpgrade :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVoipCallCoordinatorWithAppDeterminedUpgrade>
    {
        IVoipCallCoordinatorWithAppDeterminedUpgrade(std::nullptr_t = nullptr) noexcept {}
        IVoipCallCoordinatorWithAppDeterminedUpgrade(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVoipCallCoordinatorWithUpgrade :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVoipCallCoordinatorWithUpgrade>
    {
        IVoipCallCoordinatorWithUpgrade(std::nullptr_t = nullptr) noexcept {}
        IVoipCallCoordinatorWithUpgrade(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVoipOperation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVoipOperation>
    {
        IVoipOperation(std::nullptr_t = nullptr) noexcept {}
        IVoipOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVoipOperationsManager :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVoipOperationsManager>
    {
        IVoipOperationsManager(std::nullptr_t = nullptr) noexcept {}
        IVoipOperationsManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVoipPhoneCall :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVoipPhoneCall>
    {
        IVoipPhoneCall(std::nullptr_t = nullptr) noexcept {}
        IVoipPhoneCall(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVoipPhoneCall2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVoipPhoneCall2>,
        impl::require<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall2, winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall>
    {
        IVoipPhoneCall2(std::nullptr_t = nullptr) noexcept {}
        IVoipPhoneCall2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVoipPhoneCall3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVoipPhoneCall3>,
        impl::require<winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall3, winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall, winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall2>
    {
        IVoipPhoneCall3(std::nullptr_t = nullptr) noexcept {}
        IVoipPhoneCall3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVoipPhoneCallReady :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVoipPhoneCallReady>
    {
        IVoipPhoneCallReady(std::nullptr_t = nullptr) noexcept {}
        IVoipPhoneCallReady(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
