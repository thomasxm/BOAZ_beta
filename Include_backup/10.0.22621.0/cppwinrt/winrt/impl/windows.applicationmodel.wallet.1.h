// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Wallet_1_H
#define WINRT_Windows_ApplicationModel_Wallet_1_H
#include "winrt/impl/Windows.ApplicationModel.Wallet.0.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Wallet
{
    struct __declspec(empty_bases) IWalletBarcode :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWalletBarcode>
    {
        IWalletBarcode(std::nullptr_t = nullptr) noexcept {}
        IWalletBarcode(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWalletBarcodeFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWalletBarcodeFactory>
    {
        IWalletBarcodeFactory(std::nullptr_t = nullptr) noexcept {}
        IWalletBarcodeFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWalletItem :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWalletItem>
    {
        IWalletItem(std::nullptr_t = nullptr) noexcept {}
        IWalletItem(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWalletItemCustomProperty :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWalletItemCustomProperty>
    {
        IWalletItemCustomProperty(std::nullptr_t = nullptr) noexcept {}
        IWalletItemCustomProperty(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWalletItemCustomPropertyFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWalletItemCustomPropertyFactory>
    {
        IWalletItemCustomPropertyFactory(std::nullptr_t = nullptr) noexcept {}
        IWalletItemCustomPropertyFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWalletItemFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWalletItemFactory>
    {
        IWalletItemFactory(std::nullptr_t = nullptr) noexcept {}
        IWalletItemFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWalletItemStore :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWalletItemStore>
    {
        IWalletItemStore(std::nullptr_t = nullptr) noexcept {}
        IWalletItemStore(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWalletItemStore2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWalletItemStore2>
    {
        IWalletItemStore2(std::nullptr_t = nullptr) noexcept {}
        IWalletItemStore2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWalletManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWalletManagerStatics>
    {
        IWalletManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IWalletManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWalletRelevantLocation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWalletRelevantLocation>
    {
        IWalletRelevantLocation(std::nullptr_t = nullptr) noexcept {}
        IWalletRelevantLocation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWalletTransaction :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWalletTransaction>
    {
        IWalletTransaction(std::nullptr_t = nullptr) noexcept {}
        IWalletTransaction(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWalletVerb :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWalletVerb>
    {
        IWalletVerb(std::nullptr_t = nullptr) noexcept {}
        IWalletVerb(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWalletVerbFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWalletVerbFactory>
    {
        IWalletVerbFactory(std::nullptr_t = nullptr) noexcept {}
        IWalletVerbFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
