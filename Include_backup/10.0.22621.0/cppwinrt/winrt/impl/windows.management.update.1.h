// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Management_Update_1_H
#define WINRT_Windows_Management_Update_1_H
#include "winrt/impl/Windows.Management.Update.0.h"
WINRT_EXPORT namespace winrt::Windows::Management::Update
{
    struct __declspec(empty_bases) IPreviewBuildsManager :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPreviewBuildsManager>
    {
        IPreviewBuildsManager(std::nullptr_t = nullptr) noexcept {}
        IPreviewBuildsManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPreviewBuildsManagerStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPreviewBuildsManagerStatics>
    {
        IPreviewBuildsManagerStatics(std::nullptr_t = nullptr) noexcept {}
        IPreviewBuildsManagerStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPreviewBuildsState :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPreviewBuildsState>
    {
        IPreviewBuildsState(std::nullptr_t = nullptr) noexcept {}
        IPreviewBuildsState(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowsUpdate :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowsUpdate>
    {
        IWindowsUpdate(std::nullptr_t = nullptr) noexcept {}
        IWindowsUpdate(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowsUpdateActionCompletedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowsUpdateActionCompletedEventArgs>
    {
        IWindowsUpdateActionCompletedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IWindowsUpdateActionCompletedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowsUpdateActionProgress :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowsUpdateActionProgress>
    {
        IWindowsUpdateActionProgress(std::nullptr_t = nullptr) noexcept {}
        IWindowsUpdateActionProgress(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowsUpdateActionResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowsUpdateActionResult>
    {
        IWindowsUpdateActionResult(std::nullptr_t = nullptr) noexcept {}
        IWindowsUpdateActionResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowsUpdateAdministrator :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowsUpdateAdministrator>
    {
        IWindowsUpdateAdministrator(std::nullptr_t = nullptr) noexcept {}
        IWindowsUpdateAdministrator(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowsUpdateAdministratorStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowsUpdateAdministratorStatics>
    {
        IWindowsUpdateAdministratorStatics(std::nullptr_t = nullptr) noexcept {}
        IWindowsUpdateAdministratorStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowsUpdateApprovalData :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowsUpdateApprovalData>
    {
        IWindowsUpdateApprovalData(std::nullptr_t = nullptr) noexcept {}
        IWindowsUpdateApprovalData(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowsUpdateAttentionRequiredInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowsUpdateAttentionRequiredInfo>
    {
        IWindowsUpdateAttentionRequiredInfo(std::nullptr_t = nullptr) noexcept {}
        IWindowsUpdateAttentionRequiredInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowsUpdateAttentionRequiredReasonChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowsUpdateAttentionRequiredReasonChangedEventArgs>
    {
        IWindowsUpdateAttentionRequiredReasonChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IWindowsUpdateAttentionRequiredReasonChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowsUpdateGetAdministratorResult :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowsUpdateGetAdministratorResult>
    {
        IWindowsUpdateGetAdministratorResult(std::nullptr_t = nullptr) noexcept {}
        IWindowsUpdateGetAdministratorResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowsUpdateItem :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowsUpdateItem>
    {
        IWindowsUpdateItem(std::nullptr_t = nullptr) noexcept {}
        IWindowsUpdateItem(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowsUpdateManager :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowsUpdateManager>
    {
        IWindowsUpdateManager(std::nullptr_t = nullptr) noexcept {}
        IWindowsUpdateManager(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowsUpdateManagerFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowsUpdateManagerFactory>
    {
        IWindowsUpdateManagerFactory(std::nullptr_t = nullptr) noexcept {}
        IWindowsUpdateManagerFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowsUpdateProgressChangedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowsUpdateProgressChangedEventArgs>
    {
        IWindowsUpdateProgressChangedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IWindowsUpdateProgressChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowsUpdateRestartRequestOptions :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowsUpdateRestartRequestOptions>
    {
        IWindowsUpdateRestartRequestOptions(std::nullptr_t = nullptr) noexcept {}
        IWindowsUpdateRestartRequestOptions(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowsUpdateRestartRequestOptionsFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowsUpdateRestartRequestOptionsFactory>
    {
        IWindowsUpdateRestartRequestOptionsFactory(std::nullptr_t = nullptr) noexcept {}
        IWindowsUpdateRestartRequestOptionsFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IWindowsUpdateScanCompletedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IWindowsUpdateScanCompletedEventArgs>
    {
        IWindowsUpdateScanCompletedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IWindowsUpdateScanCompletedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
