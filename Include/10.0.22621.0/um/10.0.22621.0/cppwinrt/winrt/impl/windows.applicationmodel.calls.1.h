// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Calls_1_H
#define WINRT_Windows_ApplicationModel_Calls_1_H
#include "winrt/impl/Windows.ApplicationModel.Calls.0.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Calls
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
    struct __declspec(empty_bases) ILockScreenCallEndCallDeferral :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILockScreenCallEndCallDeferral>
    {
        ILockScreenCallEndCallDeferral(std::nullptr_t = nullptr) noexcept {}
        ILockScreenCallEndCallDeferral(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILockScreenCallEndRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILockScreenCallEndRequestedEventArgs>
    {
        ILockScreenCallEndRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ILockScreenCallEndRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ILockScreenCallUI :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ILockScreenCallUI>
    {
        ILockScreenCallUI(std::nullptr_t = nullptr) noexcept {}
        ILockScreenCallUI(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IMuteChangeEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IMuteChangeEventArgs>
    {
        IMuteChangeEventArgs(std::nullptr_t = nullptr) noexcept {}
        IMuteChangeEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneCall :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneCall>
    {
        IPhoneCall(std::nullptr_t = nullptr) noexcept {}
        IPhoneCall(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneCallBlockingStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneCallBlockingStatics>
    {
        IPhoneCallBlockingStatics(std::nullptr_t = nullptr) noexcept {}
        IPhoneCallBlockingStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneCallHistoryEntry :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneCallHistoryEntry>
    {
        IPhoneCallHistoryEntry(std::nullptr_t = nullptr) noexcept {}
        IPhoneCallHistoryEntry(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneCallHistoryEntryAddress :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneCallHistoryEntryAddress>
    {
        IPhoneCallHistoryEntryAddress(std::nullptr_t = nullptr) noexcept {}
        IPhoneCallHistoryEntryAddress(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneCallHistoryEntryAddressFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneCallHistoryEntryAddressFactory>
    {
        IPhoneCallHistoryEntryAddressFactory(std::nullptr_t = nullptr) noexcept {}
        IPhoneCallHistoryEntryAddressFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneCallHistoryEntryQueryOptions :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneCallHistoryEntryQueryOptions>
    {
        IPhoneCallHistoryEntryQueryOptions(std::nullptr_t = nullptr) noexcept {}
        IPhoneCallHistoryEntryQueryOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneCallHistoryEntryReader :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneCallHistoryEntryReader>
    {
        IPhoneCallHistoryEntryReader(std::nullptr_t = nullptr) noexcept {}
        IPhoneCallHistoryEntryReader(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneCallHistoryManagerForUser :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneCallHistoryManagerForUser>
    {
        IPhoneCallHistoryManagerForUser(std::nullptr_t = nullptr) noexcept {}
        IPhoneCallHistoryManagerForUser(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneCallHistoryManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneCallHistoryManagerStatics>
    {
        IPhoneCallHistoryManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IPhoneCallHistoryManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneCallHistoryManagerStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneCallHistoryManagerStatics2>
    {
        IPhoneCallHistoryManagerStatics2(std::nullptr_t = nullptr) noexcept {}
        IPhoneCallHistoryManagerStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneCallHistoryStore :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneCallHistoryStore>
    {
        IPhoneCallHistoryStore(std::nullptr_t = nullptr) noexcept {}
        IPhoneCallHistoryStore(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneCallInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneCallInfo>
    {
        IPhoneCallInfo(std::nullptr_t = nullptr) noexcept {}
        IPhoneCallInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneCallManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneCallManagerStatics>
    {
        IPhoneCallManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IPhoneCallManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneCallManagerStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneCallManagerStatics2>
    {
        IPhoneCallManagerStatics2(std::nullptr_t = nullptr) noexcept {}
        IPhoneCallManagerStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneCallStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneCallStatics>
    {
        IPhoneCallStatics(std::nullptr_t = nullptr) noexcept {}
        IPhoneCallStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneCallStore :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneCallStore>
    {
        IPhoneCallStore(std::nullptr_t = nullptr) noexcept {}
        IPhoneCallStore(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneCallVideoCapabilities :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneCallVideoCapabilities>
    {
        IPhoneCallVideoCapabilities(std::nullptr_t = nullptr) noexcept {}
        IPhoneCallVideoCapabilities(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneCallVideoCapabilitiesManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneCallVideoCapabilitiesManagerStatics>
    {
        IPhoneCallVideoCapabilitiesManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IPhoneCallVideoCapabilitiesManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneCallsResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneCallsResult>
    {
        IPhoneCallsResult(std::nullptr_t = nullptr) noexcept {}
        IPhoneCallsResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneDialOptions :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneDialOptions>
    {
        IPhoneDialOptions(std::nullptr_t = nullptr) noexcept {}
        IPhoneDialOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneLine :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneLine>
    {
        IPhoneLine(std::nullptr_t = nullptr) noexcept {}
        IPhoneLine(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneLine2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneLine2>
    {
        IPhoneLine2(std::nullptr_t = nullptr) noexcept {}
        IPhoneLine2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneLine3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneLine3>
    {
        IPhoneLine3(std::nullptr_t = nullptr) noexcept {}
        IPhoneLine3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneLineCellularDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneLineCellularDetails>
    {
        IPhoneLineCellularDetails(std::nullptr_t = nullptr) noexcept {}
        IPhoneLineCellularDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneLineConfiguration :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneLineConfiguration>
    {
        IPhoneLineConfiguration(std::nullptr_t = nullptr) noexcept {}
        IPhoneLineConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneLineDialResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneLineDialResult>
    {
        IPhoneLineDialResult(std::nullptr_t = nullptr) noexcept {}
        IPhoneLineDialResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneLineStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneLineStatics>
    {
        IPhoneLineStatics(std::nullptr_t = nullptr) noexcept {}
        IPhoneLineStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneLineTransportDevice :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneLineTransportDevice>
    {
        IPhoneLineTransportDevice(std::nullptr_t = nullptr) noexcept {}
        IPhoneLineTransportDevice(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneLineTransportDevice2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneLineTransportDevice2>
    {
        IPhoneLineTransportDevice2(std::nullptr_t = nullptr) noexcept {}
        IPhoneLineTransportDevice2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneLineTransportDeviceStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneLineTransportDeviceStatics>
    {
        IPhoneLineTransportDeviceStatics(std::nullptr_t = nullptr) noexcept {}
        IPhoneLineTransportDeviceStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneLineWatcher :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneLineWatcher>
    {
        IPhoneLineWatcher(std::nullptr_t = nullptr) noexcept {}
        IPhoneLineWatcher(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneLineWatcherEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneLineWatcherEventArgs>
    {
        IPhoneLineWatcherEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPhoneLineWatcherEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneVoicemail :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneVoicemail>
    {
        IPhoneVoicemail(std::nullptr_t = nullptr) noexcept {}
        IPhoneVoicemail(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
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
        impl::require<winrt::Windows::ApplicationModel::Calls::IVoipCallCoordinator2, winrt::Windows::ApplicationModel::Calls::IVoipCallCoordinator>
    {
        IVoipCallCoordinator2(std::nullptr_t = nullptr) noexcept {}
        IVoipCallCoordinator2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVoipCallCoordinator3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVoipCallCoordinator3>,
        impl::require<winrt::Windows::ApplicationModel::Calls::IVoipCallCoordinator3, winrt::Windows::ApplicationModel::Calls::IVoipCallCoordinator>
    {
        IVoipCallCoordinator3(std::nullptr_t = nullptr) noexcept {}
        IVoipCallCoordinator3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
        using impl::consume_t<IVoipCallCoordinator3, IVoipCallCoordinator3>::RequestNewIncomingCall;
        using impl::consume_t<IVoipCallCoordinator3, winrt::Windows::ApplicationModel::Calls::IVoipCallCoordinator>::RequestNewIncomingCall;
    };
    struct __declspec(empty_bases) IVoipCallCoordinator4 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVoipCallCoordinator4>,
        impl::require<winrt::Windows::ApplicationModel::Calls::IVoipCallCoordinator4, winrt::Windows::ApplicationModel::Calls::IVoipCallCoordinator>
    {
        IVoipCallCoordinator4(std::nullptr_t = nullptr) noexcept {}
        IVoipCallCoordinator4(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
        using impl::consume_t<IVoipCallCoordinator4, IVoipCallCoordinator4>::ReserveCallResourcesAsync;
        using impl::consume_t<IVoipCallCoordinator4, winrt::Windows::ApplicationModel::Calls::IVoipCallCoordinator>::ReserveCallResourcesAsync;
    };
    struct __declspec(empty_bases) IVoipCallCoordinatorStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVoipCallCoordinatorStatics>
    {
        IVoipCallCoordinatorStatics(std::nullptr_t = nullptr) noexcept {}
        IVoipCallCoordinatorStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
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
        impl::require<winrt::Windows::ApplicationModel::Calls::IVoipPhoneCall2, winrt::Windows::ApplicationModel::Calls::IVoipPhoneCall>
    {
        IVoipPhoneCall2(std::nullptr_t = nullptr) noexcept {}
        IVoipPhoneCall2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVoipPhoneCall3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVoipPhoneCall3>,
        impl::require<winrt::Windows::ApplicationModel::Calls::IVoipPhoneCall3, winrt::Windows::ApplicationModel::Calls::IVoipPhoneCall, winrt::Windows::ApplicationModel::Calls::IVoipPhoneCall2>
    {
        IVoipPhoneCall3(std::nullptr_t = nullptr) noexcept {}
        IVoipPhoneCall3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
