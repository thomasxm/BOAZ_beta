// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Storage_BulkAccess_1_H
#define WINRT_Windows_Storage_BulkAccess_1_H
#include "winrt/impl/Windows.Storage.BulkAccess.0.h"
WINRT_EXPORT namespace winrt::Windows::Storage::BulkAccess
{
    struct __declspec(empty_bases) IFileInformationFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IFileInformationFactory>
    {
        IFileInformationFactory(std::nullptr_t = nullptr) noexcept {}
        IFileInformationFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IFileInformationFactoryFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IFileInformationFactoryFactory>
    {
        IFileInformationFactoryFactory(std::nullptr_t = nullptr) noexcept {}
        IFileInformationFactoryFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IStorageItemInformation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IStorageItemInformation>
    {
        IStorageItemInformation(std::nullptr_t = nullptr) noexcept {}
        IStorageItemInformation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
