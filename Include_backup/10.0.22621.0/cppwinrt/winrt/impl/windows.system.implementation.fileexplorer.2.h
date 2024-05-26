// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_Implementation_FileExplorer_2_H
#define WINRT_Windows_System_Implementation_FileExplorer_2_H
#include "winrt/impl/Windows.System.Implementation.FileExplorer.1.h"
WINRT_EXPORT namespace winrt::Windows::System::Implementation::FileExplorer
{
    struct __declspec(empty_bases) SysStorageProviderEventReceivedEventArgs : winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderEventReceivedEventArgs
    {
        SysStorageProviderEventReceivedEventArgs(std::nullptr_t) noexcept {}
        SysStorageProviderEventReceivedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::System::Implementation::FileExplorer::ISysStorageProviderEventReceivedEventArgs(ptr, take_ownership_from_abi) {}
        explicit SysStorageProviderEventReceivedEventArgs(param::hstring const& json);
    };
}
#endif
