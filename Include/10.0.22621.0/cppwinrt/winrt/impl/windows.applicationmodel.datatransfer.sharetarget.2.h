// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_DataTransfer_ShareTarget_2_H
#define WINRT_Windows_ApplicationModel_DataTransfer_ShareTarget_2_H
#include "winrt/impl/Windows.ApplicationModel.DataTransfer.ShareTarget.1.h"
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::DataTransfer::ShareTarget
{
    struct __declspec(empty_bases) QuickLink : winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink
    {
        QuickLink(std::nullptr_t) noexcept {}
        QuickLink(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IQuickLink(ptr, take_ownership_from_abi) {}
        QuickLink();
    };
    struct __declspec(empty_bases) ShareOperation : winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation,
        impl::require<ShareOperation, winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation2, winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation3>
    {
        ShareOperation(std::nullptr_t) noexcept {}
        ShareOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::ApplicationModel::DataTransfer::ShareTarget::IShareOperation(ptr, take_ownership_from_abi) {}
    };
}
#endif
