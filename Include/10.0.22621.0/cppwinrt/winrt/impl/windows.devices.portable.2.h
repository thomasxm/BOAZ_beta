// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Portable_2_H
#define WINRT_Windows_Devices_Portable_2_H
#include "winrt/impl/Windows.Devices.Portable.1.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Portable
{
    struct ServiceDevice
    {
        ServiceDevice() = delete;
        static auto GetDeviceSelector(winrt::Windows::Devices::Portable::ServiceDeviceType const& serviceType);
        static auto GetDeviceSelectorFromServiceId(winrt::guid const& serviceId);
    };
    struct StorageDevice
    {
        StorageDevice() = delete;
        static auto FromId(param::hstring const& deviceId);
        static auto GetDeviceSelector();
    };
}
#endif
