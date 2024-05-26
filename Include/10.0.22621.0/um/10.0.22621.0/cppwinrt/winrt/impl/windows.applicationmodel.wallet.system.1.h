// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Wallet_System_1_H
#define WINRT_Windows_ApplicationModel_Wallet_System_1_H
#include "winrt/impl/Windows.ApplicationModel.Wallet.System.0.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Wallet::System
{
    struct __declspec(empty_bases) IWalletItemSystemStore :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWalletItemSystemStore>
    {
        IWalletItemSystemStore(std::nullptr_t = nullptr) noexcept {}
        IWalletItemSystemStore(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWalletItemSystemStore2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWalletItemSystemStore2>
    {
        IWalletItemSystemStore2(std::nullptr_t = nullptr) noexcept {}
        IWalletItemSystemStore2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWalletManagerSystemStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWalletManagerSystemStatics>
    {
        IWalletManagerSystemStatics(std::nullptr_t = nullptr) noexcept {}
        IWalletManagerSystemStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
