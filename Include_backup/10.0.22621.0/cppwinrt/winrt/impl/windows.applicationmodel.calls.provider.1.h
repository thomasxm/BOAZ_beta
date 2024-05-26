// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Calls_Provider_1_H
#define WINRT_Windows_ApplicationModel_Calls_Provider_1_H
#include "winrt/impl/Windows.ApplicationModel.Calls.Provider.0.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Calls::Provider
{
    struct __declspec(empty_bases) IPhoneCallOrigin :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneCallOrigin>
    {
        IPhoneCallOrigin(std::nullptr_t = nullptr) noexcept {}
        IPhoneCallOrigin(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneCallOrigin2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneCallOrigin2>,
        impl::require<winrt::Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin2, winrt::Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin>
    {
        IPhoneCallOrigin2(std::nullptr_t = nullptr) noexcept {}
        IPhoneCallOrigin2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneCallOrigin3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneCallOrigin3>,
        impl::require<winrt::Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin3, winrt::Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin, winrt::Windows::ApplicationModel::Calls::Provider::IPhoneCallOrigin2>
    {
        IPhoneCallOrigin3(std::nullptr_t = nullptr) noexcept {}
        IPhoneCallOrigin3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneCallOriginManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneCallOriginManagerStatics>
    {
        IPhoneCallOriginManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IPhoneCallOriginManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneCallOriginManagerStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneCallOriginManagerStatics2>,
        impl::require<winrt::Windows::ApplicationModel::Calls::Provider::IPhoneCallOriginManagerStatics2, winrt::Windows::ApplicationModel::Calls::Provider::IPhoneCallOriginManagerStatics>
    {
        IPhoneCallOriginManagerStatics2(std::nullptr_t = nullptr) noexcept {}
        IPhoneCallOriginManagerStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPhoneCallOriginManagerStatics3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPhoneCallOriginManagerStatics3>
    {
        IPhoneCallOriginManagerStatics3(std::nullptr_t = nullptr) noexcept {}
        IPhoneCallOriginManagerStatics3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
