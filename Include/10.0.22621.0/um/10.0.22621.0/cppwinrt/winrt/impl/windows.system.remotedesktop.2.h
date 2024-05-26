// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_RemoteDesktop_2_H
#define WINRT_Windows_System_RemoteDesktop_2_H
#include "winrt/impl/Windows.System.RemoteDesktop.1.h"
WINRT_EXPORT namespace winrt::Windows::System::RemoteDesktop
{
    struct InteractiveSession
    {
        InteractiveSession() = delete;
        [[nodiscard]] static auto IsRemote();
    };
}
#endif
