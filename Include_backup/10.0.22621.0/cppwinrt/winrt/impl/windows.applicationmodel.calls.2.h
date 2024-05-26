// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Calls_2_H
#define WINRT_Windows_ApplicationModel_Calls_2_H
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.System.1.h"
#include "winrt/impl/Windows.ApplicationModel.Calls.1.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Calls
{
    struct __declspec(empty_bases) CallAnswerEventArgs : winrt::Windows::ApplicationModel::Calls::ICallAnswerEventArgs
    {
        CallAnswerEventArgs(std::nullptr_t) noexcept {}
        CallAnswerEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::ICallAnswerEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) CallRejectEventArgs : winrt::Windows::ApplicationModel::Calls::ICallRejectEventArgs
    {
        CallRejectEventArgs(std::nullptr_t) noexcept {}
        CallRejectEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::ICallRejectEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) CallStateChangeEventArgs : winrt::Windows::ApplicationModel::Calls::ICallStateChangeEventArgs
    {
        CallStateChangeEventArgs(std::nullptr_t) noexcept {}
        CallStateChangeEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::ICallStateChangeEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) LockScreenCallEndCallDeferral : winrt::Windows::ApplicationModel::Calls::ILockScreenCallEndCallDeferral
    {
        LockScreenCallEndCallDeferral(std::nullptr_t) noexcept {}
        LockScreenCallEndCallDeferral(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::ILockScreenCallEndCallDeferral(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) LockScreenCallEndRequestedEventArgs : winrt::Windows::ApplicationModel::Calls::ILockScreenCallEndRequestedEventArgs
    {
        LockScreenCallEndRequestedEventArgs(std::nullptr_t) noexcept {}
        LockScreenCallEndRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::ILockScreenCallEndRequestedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) LockScreenCallUI : winrt::Windows::ApplicationModel::Calls::ILockScreenCallUI
    {
        LockScreenCallUI(std::nullptr_t) noexcept {}
        LockScreenCallUI(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::ILockScreenCallUI(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) MuteChangeEventArgs : winrt::Windows::ApplicationModel::Calls::IMuteChangeEventArgs
    {
        MuteChangeEventArgs(std::nullptr_t) noexcept {}
        MuteChangeEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::IMuteChangeEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PhoneCall : winrt::Windows::ApplicationModel::Calls::IPhoneCall
    {
        PhoneCall(std::nullptr_t) noexcept {}
        PhoneCall(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::IPhoneCall(ptr, take_ownership_from_abi) {}
        static auto GetFromId(param::hstring const& callId);
    };
    struct PhoneCallBlocking
    {
        PhoneCallBlocking() = delete;
        [[nodiscard]] static auto BlockUnknownNumbers();
        static auto BlockUnknownNumbers(bool value);
        [[nodiscard]] static auto BlockPrivateNumbers();
        static auto BlockPrivateNumbers(bool value);
        static auto SetCallBlockingListAsync(param::async_iterable<hstring> const& phoneNumberList);
    };
    struct __declspec(empty_bases) PhoneCallHistoryEntry : winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry
    {
        PhoneCallHistoryEntry(std::nullptr_t) noexcept {}
        PhoneCallHistoryEntry(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntry(ptr, take_ownership_from_abi) {}
        PhoneCallHistoryEntry();
    };
    struct __declspec(empty_bases) PhoneCallHistoryEntryAddress : winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryAddress
    {
        PhoneCallHistoryEntryAddress(std::nullptr_t) noexcept {}
        PhoneCallHistoryEntryAddress(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryAddress(ptr, take_ownership_from_abi) {}
        PhoneCallHistoryEntryAddress();
        PhoneCallHistoryEntryAddress(param::hstring const& rawAddress, winrt::Windows::ApplicationModel::Calls::PhoneCallHistoryEntryRawAddressKind const& rawAddressKind);
    };
    struct __declspec(empty_bases) PhoneCallHistoryEntryQueryOptions : winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryQueryOptions
    {
        PhoneCallHistoryEntryQueryOptions(std::nullptr_t) noexcept {}
        PhoneCallHistoryEntryQueryOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryQueryOptions(ptr, take_ownership_from_abi) {}
        PhoneCallHistoryEntryQueryOptions();
    };
    struct __declspec(empty_bases) PhoneCallHistoryEntryReader : winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryReader
    {
        PhoneCallHistoryEntryReader(std::nullptr_t) noexcept {}
        PhoneCallHistoryEntryReader(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryEntryReader(ptr, take_ownership_from_abi) {}
    };
    struct PhoneCallHistoryManager
    {
        PhoneCallHistoryManager() = delete;
        static auto RequestStoreAsync(winrt::Windows::ApplicationModel::Calls::PhoneCallHistoryStoreAccessType const& accessType);
        static auto GetForUser(winrt::Windows::System::User const& user);
    };
    struct __declspec(empty_bases) PhoneCallHistoryManagerForUser : winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryManagerForUser
    {
        PhoneCallHistoryManagerForUser(std::nullptr_t) noexcept {}
        PhoneCallHistoryManagerForUser(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryManagerForUser(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PhoneCallHistoryStore : winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryStore
    {
        PhoneCallHistoryStore(std::nullptr_t) noexcept {}
        PhoneCallHistoryStore(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::IPhoneCallHistoryStore(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PhoneCallInfo : winrt::Windows::ApplicationModel::Calls::IPhoneCallInfo
    {
        PhoneCallInfo(std::nullptr_t) noexcept {}
        PhoneCallInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::IPhoneCallInfo(ptr, take_ownership_from_abi) {}
    };
    struct PhoneCallManager
    {
        PhoneCallManager() = delete;
        static auto ShowPhoneCallUI(param::hstring const& phoneNumber, param::hstring const& displayName);
        static auto CallStateChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        using CallStateChanged_revoker = impl::factory_event_revoker<winrt::Windows::ApplicationModel::Calls::IPhoneCallManagerStatics2, &impl::abi_t<winrt::Windows::ApplicationModel::Calls::IPhoneCallManagerStatics2>::remove_CallStateChanged>;
        [[nodiscard]] static CallStateChanged_revoker CallStateChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler);
        static auto CallStateChanged(winrt::event_token const& token);
        [[nodiscard]] static auto IsCallActive();
        [[nodiscard]] static auto IsCallIncoming();
        static auto ShowPhoneCallSettingsUI();
        static auto RequestStoreAsync();
    };
    struct __declspec(empty_bases) PhoneCallStore : winrt::Windows::ApplicationModel::Calls::IPhoneCallStore
    {
        PhoneCallStore(std::nullptr_t) noexcept {}
        PhoneCallStore(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::IPhoneCallStore(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PhoneCallVideoCapabilities : winrt::Windows::ApplicationModel::Calls::IPhoneCallVideoCapabilities
    {
        PhoneCallVideoCapabilities(std::nullptr_t) noexcept {}
        PhoneCallVideoCapabilities(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::IPhoneCallVideoCapabilities(ptr, take_ownership_from_abi) {}
    };
    struct PhoneCallVideoCapabilitiesManager
    {
        PhoneCallVideoCapabilitiesManager() = delete;
        static auto GetCapabilitiesAsync(param::hstring const& phoneNumber);
    };
    struct __declspec(empty_bases) PhoneCallsResult : winrt::Windows::ApplicationModel::Calls::IPhoneCallsResult
    {
        PhoneCallsResult(std::nullptr_t) noexcept {}
        PhoneCallsResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::IPhoneCallsResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PhoneDialOptions : winrt::Windows::ApplicationModel::Calls::IPhoneDialOptions
    {
        PhoneDialOptions(std::nullptr_t) noexcept {}
        PhoneDialOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::IPhoneDialOptions(ptr, take_ownership_from_abi) {}
        PhoneDialOptions();
    };
    struct __declspec(empty_bases) PhoneLine : winrt::Windows::ApplicationModel::Calls::IPhoneLine,
        impl::require<PhoneLine, winrt::Windows::ApplicationModel::Calls::IPhoneLine2, winrt::Windows::ApplicationModel::Calls::IPhoneLine3>
    {
        PhoneLine(std::nullptr_t) noexcept {}
        PhoneLine(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::IPhoneLine(ptr, take_ownership_from_abi) {}
        static auto FromIdAsync(winrt::guid const& lineId);
    };
    struct __declspec(empty_bases) PhoneLineCellularDetails : winrt::Windows::ApplicationModel::Calls::IPhoneLineCellularDetails
    {
        PhoneLineCellularDetails(std::nullptr_t) noexcept {}
        PhoneLineCellularDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::IPhoneLineCellularDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PhoneLineConfiguration : winrt::Windows::ApplicationModel::Calls::IPhoneLineConfiguration
    {
        PhoneLineConfiguration(std::nullptr_t) noexcept {}
        PhoneLineConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::IPhoneLineConfiguration(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PhoneLineDialResult : winrt::Windows::ApplicationModel::Calls::IPhoneLineDialResult
    {
        PhoneLineDialResult(std::nullptr_t) noexcept {}
        PhoneLineDialResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::IPhoneLineDialResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PhoneLineTransportDevice : winrt::Windows::ApplicationModel::Calls::IPhoneLineTransportDevice,
        impl::require<PhoneLineTransportDevice, winrt::Windows::ApplicationModel::Calls::IPhoneLineTransportDevice2>
    {
        PhoneLineTransportDevice(std::nullptr_t) noexcept {}
        PhoneLineTransportDevice(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::IPhoneLineTransportDevice(ptr, take_ownership_from_abi) {}
        static auto FromId(param::hstring const& id);
        static auto GetDeviceSelector();
        static auto GetDeviceSelector(winrt::Windows::ApplicationModel::Calls::PhoneLineTransport const& transport);
    };
    struct __declspec(empty_bases) PhoneLineWatcher : winrt::Windows::ApplicationModel::Calls::IPhoneLineWatcher
    {
        PhoneLineWatcher(std::nullptr_t) noexcept {}
        PhoneLineWatcher(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::IPhoneLineWatcher(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PhoneLineWatcherEventArgs : winrt::Windows::ApplicationModel::Calls::IPhoneLineWatcherEventArgs
    {
        PhoneLineWatcherEventArgs(std::nullptr_t) noexcept {}
        PhoneLineWatcherEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::IPhoneLineWatcherEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PhoneVoicemail : winrt::Windows::ApplicationModel::Calls::IPhoneVoicemail
    {
        PhoneVoicemail(std::nullptr_t) noexcept {}
        PhoneVoicemail(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::IPhoneVoicemail(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) VoipCallCoordinator : winrt::Windows::ApplicationModel::Calls::IVoipCallCoordinator,
        impl::require<VoipCallCoordinator, winrt::Windows::ApplicationModel::Calls::IVoipCallCoordinator2, winrt::Windows::ApplicationModel::Calls::IVoipCallCoordinator3, winrt::Windows::ApplicationModel::Calls::IVoipCallCoordinator4>
    {
        VoipCallCoordinator(std::nullptr_t) noexcept {}
        VoipCallCoordinator(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::IVoipCallCoordinator(ptr, take_ownership_from_abi) {}
        using winrt::Windows::ApplicationModel::Calls::IVoipCallCoordinator::RequestNewIncomingCall;
        using impl::consume_t<VoipCallCoordinator, winrt::Windows::ApplicationModel::Calls::IVoipCallCoordinator3>::RequestNewIncomingCall;
        using winrt::Windows::ApplicationModel::Calls::IVoipCallCoordinator::ReserveCallResourcesAsync;
        using impl::consume_t<VoipCallCoordinator, winrt::Windows::ApplicationModel::Calls::IVoipCallCoordinator4>::ReserveCallResourcesAsync;
        static auto GetDefault();
    };
    struct __declspec(empty_bases) VoipPhoneCall : winrt::Windows::ApplicationModel::Calls::IVoipPhoneCall,
        impl::require<VoipPhoneCall, winrt::Windows::ApplicationModel::Calls::IVoipPhoneCall2, winrt::Windows::ApplicationModel::Calls::IVoipPhoneCall3>
    {
        VoipPhoneCall(std::nullptr_t) noexcept {}
        VoipPhoneCall(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::IVoipPhoneCall(ptr, take_ownership_from_abi) {}
    };
}
#endif
