// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Wallet_System_2_H
#define WINRT_Windows_ApplicationModel_Wallet_System_2_H
#include "winrt/impl/Windows.ApplicationModel.Wallet.System.1.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Wallet::System
{
    struct __declspec(empty_bases) WalletItemSystemStore : winrt::Windows::ApplicationModel::Wallet::System::IWalletItemSystemStore,
        impl::require<WalletItemSystemStore, winrt::Windows::ApplicationModel::Wallet::System::IWalletItemSystemStore2>
    {
        WalletItemSystemStore(std::nullptr_t) noexcept {}
        WalletItemSystemStore(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::Wallet::System::IWalletItemSystemStore(ptr, take_ownership_from_abi) {}
    };
    struct WalletManagerSystem
    {
        WalletManagerSystem() = delete;
        static auto RequestStoreAsync();
    };
}
#endif
