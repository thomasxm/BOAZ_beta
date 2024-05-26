// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Calls_Background_1_H
#define WINRT_Windows_ApplicationModel_Calls_Background_1_H
#include "winrt/impl/Windows.ApplicationModel.Calls.Background.0.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Calls::Background
{
    struct __declspec(empty_bases) IPhoneCallBlockedTriggerDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneCallBlockedTriggerDetails>
    {
        IPhoneCallBlockedTriggerDetails(std::nullptr_t = nullptr) noexcept {}
        IPhoneCallBlockedTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneCallOriginDataRequestTriggerDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneCallOriginDataRequestTriggerDetails>
    {
        IPhoneCallOriginDataRequestTriggerDetails(std::nullptr_t = nullptr) noexcept {}
        IPhoneCallOriginDataRequestTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneIncomingCallDismissedTriggerDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneIncomingCallDismissedTriggerDetails>
    {
        IPhoneIncomingCallDismissedTriggerDetails(std::nullptr_t = nullptr) noexcept {}
        IPhoneIncomingCallDismissedTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneIncomingCallNotificationTriggerDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneIncomingCallNotificationTriggerDetails>
    {
        IPhoneIncomingCallNotificationTriggerDetails(std::nullptr_t = nullptr) noexcept {}
        IPhoneIncomingCallNotificationTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneLineChangedTriggerDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneLineChangedTriggerDetails>
    {
        IPhoneLineChangedTriggerDetails(std::nullptr_t = nullptr) noexcept {}
        IPhoneLineChangedTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneNewVoicemailMessageTriggerDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneNewVoicemailMessageTriggerDetails>
    {
        IPhoneNewVoicemailMessageTriggerDetails(std::nullptr_t = nullptr) noexcept {}
        IPhoneNewVoicemailMessageTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
