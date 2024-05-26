// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Storage_Pickers_Provider_1_H
#define WINRT_Windows_Storage_Pickers_Provider_1_H
#include "winrt/impl/Windows.Storage.Pickers.Provider.0.h"
WINRT_EXPORT namespace winrt::Windows::Storage::Pickers::Provider
{
    struct __declspec(empty_bases) IFileOpenPickerUI :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IFileOpenPickerUI>
    {
        IFileOpenPickerUI(std::nullptr_t = nullptr) noexcept {}
        IFileOpenPickerUI(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IFileRemovedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IFileRemovedEventArgs>
    {
        IFileRemovedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IFileRemovedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IFileSavePickerUI :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IFileSavePickerUI>
    {
        IFileSavePickerUI(std::nullptr_t = nullptr) noexcept {}
        IFileSavePickerUI(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPickerClosingDeferral :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPickerClosingDeferral>
    {
        IPickerClosingDeferral(std::nullptr_t = nullptr) noexcept {}
        IPickerClosingDeferral(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPickerClosingEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPickerClosingEventArgs>
    {
        IPickerClosingEventArgs(std::nullptr_t = nullptr) noexcept {}
        IPickerClosingEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IPickerClosingOperation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IPickerClosingOperation>
    {
        IPickerClosingOperation(std::nullptr_t = nullptr) noexcept {}
        IPickerClosingOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITargetFileRequest :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITargetFileRequest>
    {
        ITargetFileRequest(std::nullptr_t = nullptr) noexcept {}
        ITargetFileRequest(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITargetFileRequestDeferral :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITargetFileRequestDeferral>
    {
        ITargetFileRequestDeferral(std::nullptr_t = nullptr) noexcept {}
        ITargetFileRequestDeferral(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) ITargetFileRequestedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<ITargetFileRequestedEventArgs>
    {
        ITargetFileRequestedEventArgs(std::nullptr_t = nullptr) noexcept {}
        ITargetFileRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
