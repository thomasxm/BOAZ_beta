// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Management_Workplace_2_H
#define WINRT_Windows_Management_Workplace_2_H
#include "winrt/impl/Windows.Management.Workplace.1.h"
WINRT_EXPORT namespace winrt::Windows::Management::Workplace
{
    struct MdmPolicy
    {
        MdmPolicy() = delete;
        static auto IsBrowserAllowed();
        static auto IsCameraAllowed();
        static auto IsMicrosoftAccountAllowed();
        static auto IsStoreAllowed();
        static auto GetMessagingSyncPolicy();
    };
    struct WorkplaceSettings
    {
        WorkplaceSettings() = delete;
        [[nodiscard]] static auto IsMicrosoftAccountOptional();
    };
}
#endif
