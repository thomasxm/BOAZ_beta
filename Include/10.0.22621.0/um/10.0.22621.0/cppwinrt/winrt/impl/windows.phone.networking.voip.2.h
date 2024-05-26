// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Phone_Networking_Voip_2_H
#define WINRT_Windows_Phone_Networking_Voip_2_H
#include "winrt/impl/Windows.Phone.Networking.Voip.1.h"
WINRT_EXPORT namespace winrt::Windows::Phone::Networking::Voip
{
    struct __declspec(empty_bases) CallAnswerEventArgs : winrt::Windows::Phone::Networking::Voip::ICallAnswerEventArgs
    {
        CallAnswerEventArgs(std::nullptr_t) noexcept {}
        CallAnswerEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Phone::Networking::Voip::ICallAnswerEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) CallRejectEventArgs : winrt::Windows::Phone::Networking::Voip::ICallRejectEventArgs
    {
        CallRejectEventArgs(std::nullptr_t) noexcept {}
        CallRejectEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Phone::Networking::Voip::ICallRejectEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) CallStateChangeEventArgs : winrt::Windows::Phone::Networking::Voip::ICallStateChangeEventArgs
    {
        CallStateChangeEventArgs(std::nullptr_t) noexcept {}
        CallStateChangeEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Phone::Networking::Voip::ICallStateChangeEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MuteChangeEventArgs : winrt::Windows::Phone::Networking::Voip::IMuteChangeEventArgs
    {
        MuteChangeEventArgs(std::nullptr_t) noexcept {}
        MuteChangeEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Phone::Networking::Voip::IMuteChangeEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) QuerySeamlessUpgradeSupportOperation : winrt::Windows::Phone::Networking::Voip::IQuerySeamlessUpgradeSupportOperation
    {
        QuerySeamlessUpgradeSupportOperation(std::nullptr_t) noexcept {}
        QuerySeamlessUpgradeSupportOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Phone::Networking::Voip::IQuerySeamlessUpgradeSupportOperation(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) VoipCallCoordinator : winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator,
        impl::require<VoipCallCoordinator, winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinatorWithUpgrade, winrt::Windows::Phone::Networking::Voip::IVoipOperationsManager, winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinatorWithAppDeterminedUpgrade, winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator2, winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator3>
    {
        VoipCallCoordinator(std::nullptr_t) noexcept {}
        VoipCallCoordinator(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator(ptr, take_ownership_from_abi) {}
        using winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator::RequestNewIncomingCall;
        using impl::consume_t<VoipCallCoordinator, winrt::Windows::Phone::Networking::Voip::IVoipCallCoordinator3>::RequestNewIncomingCall;
        static auto GetDefault();
    };
    struct __declspec(empty_bases) VoipPhoneCall : winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall,
        impl::require<VoipPhoneCall, winrt::Windows::Phone::Networking::Voip::IVoipPhoneCallReady, winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall2, winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall3>
    {
        VoipPhoneCall(std::nullptr_t) noexcept {}
        VoipPhoneCall(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Phone::Networking::Voip::IVoipPhoneCall(ptr, take_ownership_from_abi) {}
    };
}
#endif
