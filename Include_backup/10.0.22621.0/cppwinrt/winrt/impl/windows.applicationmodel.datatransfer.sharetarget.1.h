// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_DataTransfer_ShareTarget_1_H
#define WINRT_Windows_ApplicationModel_DataTransfer_ShareTarget_1_H
#include "winrt/impl/Windows.ApplicationModel.DataTransfer.ShareTarget.0.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::DataTransfer::ShareTarget
{
    struct __declspec(empty_bases) IQuickLink :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IQuickLink>
    {
        IQuickLink(std::nullptr_t = nullptr) noexcept {}
        IQuickLink(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IShareOperation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IShareOperation>
    {
        IShareOperation(std::nullptr_t = nullptr) noexcept {}
        IShareOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IShareOperation2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IShareOperation2>
    {
        IShareOperation2(std::nullptr_t = nullptr) noexcept {}
        IShareOperation2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IShareOperation3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IShareOperation3>
    {
        IShareOperation3(std::nullptr_t = nullptr) noexcept {}
        IShareOperation3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
