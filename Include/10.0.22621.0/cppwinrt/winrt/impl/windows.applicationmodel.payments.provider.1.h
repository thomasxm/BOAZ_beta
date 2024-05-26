// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Payments_Provider_1_H
#define WINRT_Windows_ApplicationModel_Payments_Provider_1_H
#include "winrt/impl/Windows.ApplicationModel.Payments.Provider.0.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Payments::Provider
{
    struct __declspec(empty_bases) IPaymentAppCanMakePaymentTriggerDetails :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentAppCanMakePaymentTriggerDetails>
    {
        IPaymentAppCanMakePaymentTriggerDetails(std::nullptr_t = nullptr) noexcept {}
        IPaymentAppCanMakePaymentTriggerDetails(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentAppManager :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentAppManager>
    {
        IPaymentAppManager(std::nullptr_t = nullptr) noexcept {}
        IPaymentAppManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentAppManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentAppManagerStatics>
    {
        IPaymentAppManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IPaymentAppManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentTransaction :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentTransaction>
    {
        IPaymentTransaction(std::nullptr_t = nullptr) noexcept {}
        IPaymentTransaction(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentTransactionAcceptResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentTransactionAcceptResult>
    {
        IPaymentTransactionAcceptResult(std::nullptr_t = nullptr) noexcept {}
        IPaymentTransactionAcceptResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPaymentTransactionStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPaymentTransactionStatics>
    {
        IPaymentTransactionStatics(std::nullptr_t = nullptr) noexcept {}
        IPaymentTransactionStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
