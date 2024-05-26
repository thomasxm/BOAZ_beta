// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Calls_Background_2_H
#define WINRT_Windows_ApplicationModel_Calls_Background_2_H
#include "winrt/impl/Windows.ApplicationModel.Calls.Background.1.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Calls::Background
{
    struct __declspec(empty_bases) PhoneCallBlockedTriggerDetails : winrt::Windows::ApplicationModel::Calls::Background::IPhoneCallBlockedTriggerDetails
    {
        PhoneCallBlockedTriggerDetails(std::nullptr_t) noexcept {}
        PhoneCallBlockedTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::Background::IPhoneCallBlockedTriggerDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PhoneCallOriginDataRequestTriggerDetails : winrt::Windows::ApplicationModel::Calls::Background::IPhoneCallOriginDataRequestTriggerDetails
    {
        PhoneCallOriginDataRequestTriggerDetails(std::nullptr_t) noexcept {}
        PhoneCallOriginDataRequestTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::Background::IPhoneCallOriginDataRequestTriggerDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PhoneIncomingCallDismissedTriggerDetails : winrt::Windows::ApplicationModel::Calls::Background::IPhoneIncomingCallDismissedTriggerDetails
    {
        PhoneIncomingCallDismissedTriggerDetails(std::nullptr_t) noexcept {}
        PhoneIncomingCallDismissedTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::Background::IPhoneIncomingCallDismissedTriggerDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PhoneIncomingCallNotificationTriggerDetails : winrt::Windows::ApplicationModel::Calls::Background::IPhoneIncomingCallNotificationTriggerDetails
    {
        PhoneIncomingCallNotificationTriggerDetails(std::nullptr_t) noexcept {}
        PhoneIncomingCallNotificationTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::Background::IPhoneIncomingCallNotificationTriggerDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PhoneLineChangedTriggerDetails : winrt::Windows::ApplicationModel::Calls::Background::IPhoneLineChangedTriggerDetails
    {
        PhoneLineChangedTriggerDetails(std::nullptr_t) noexcept {}
        PhoneLineChangedTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::Background::IPhoneLineChangedTriggerDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PhoneNewVoicemailMessageTriggerDetails : winrt::Windows::ApplicationModel::Calls::Background::IPhoneNewVoicemailMessageTriggerDetails
    {
        PhoneNewVoicemailMessageTriggerDetails(std::nullptr_t) noexcept {}
        PhoneNewVoicemailMessageTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Calls::Background::IPhoneNewVoicemailMessageTriggerDetails(ptr, take_ownership_from_abi) {}
    };
}
#endif
