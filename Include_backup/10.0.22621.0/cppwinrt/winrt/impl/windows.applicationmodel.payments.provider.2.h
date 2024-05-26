// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Payments_Provider_2_H
#define WINRT_Windows_ApplicationModel_Payments_Provider_2_H
#include "winrt/impl/Windows.ApplicationModel.Payments.Provider.1.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Payments::Provider
{
    struct __declspec(empty_bases) PaymentAppCanMakePaymentTriggerDetails : winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppCanMakePaymentTriggerDetails
    {
        PaymentAppCanMakePaymentTriggerDetails(std::nullptr_t) noexcept {}
        PaymentAppCanMakePaymentTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppCanMakePaymentTriggerDetails(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PaymentAppManager : winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppManager
    {
        PaymentAppManager(std::nullptr_t) noexcept {}
        PaymentAppManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Payments::Provider::IPaymentAppManager(ptr, take_ownership_from_abi) {}
        [[nodiscard]] static auto Current();
    };
    struct __declspec(empty_bases) PaymentTransaction : winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransaction
    {
        PaymentTransaction(std::nullptr_t) noexcept {}
        PaymentTransaction(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransaction(ptr, take_ownership_from_abi) {}
        static auto FromIdAsync(param::hstring const& id);
    };
    struct __declspec(empty_bases) PaymentTransactionAcceptResult : winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransactionAcceptResult
    {
        PaymentTransactionAcceptResult(std::nullptr_t) noexcept {}
        PaymentTransactionAcceptResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Payments::Provider::IPaymentTransactionAcceptResult(ptr, take_ownership_from_abi) {}
    };
}
#endif
