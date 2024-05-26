// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Lights_Effects_2_H
#define WINRT_Windows_Devices_Lights_Effects_2_H
#include "winrt/impl/Windows.Devices.Lights.1.h"
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.Devices.Lights.Effects.1.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Lights::Effects
{
    struct __declspec(empty_bases) LampArrayBitmapEffect : winrt::Windows::Devices::Lights::Effects::ILampArrayBitmapEffect,
        impl::require<LampArrayBitmapEffect, winrt::Windows::Devices::Lights::Effects::ILampArrayEffect>
    {
        LampArrayBitmapEffect(std::nullptr_t) noexcept {}
        LampArrayBitmapEffect(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Lights::Effects::ILampArrayBitmapEffect(ptr, take_ownership_from_abi) {}
        LampArrayBitmapEffect(winrt::Windows::Devices::Lights::LampArray const& lampArray, array_view<int32_t const> lampIndexes);
    };
    struct __declspec(empty_bases) LampArrayBitmapRequestedEventArgs : winrt::Windows::Devices::Lights::Effects::ILampArrayBitmapRequestedEventArgs
    {
        LampArrayBitmapRequestedEventArgs(std::nullptr_t) noexcept {}
        LampArrayBitmapRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Lights::Effects::ILampArrayBitmapRequestedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) LampArrayBlinkEffect : winrt::Windows::Devices::Lights::Effects::ILampArrayBlinkEffect,
        impl::require<LampArrayBlinkEffect, winrt::Windows::Devices::Lights::Effects::ILampArrayEffect>
    {
        LampArrayBlinkEffect(std::nullptr_t) noexcept {}
        LampArrayBlinkEffect(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Lights::Effects::ILampArrayBlinkEffect(ptr, take_ownership_from_abi) {}
        LampArrayBlinkEffect(winrt::Windows::Devices::Lights::LampArray const& lampArray, array_view<int32_t const> lampIndexes);
    };
    struct __declspec(empty_bases) LampArrayColorRampEffect : winrt::Windows::Devices::Lights::Effects::ILampArrayColorRampEffect,
        impl::require<LampArrayColorRampEffect, winrt::Windows::Devices::Lights::Effects::ILampArrayEffect>
    {
        LampArrayColorRampEffect(std::nullptr_t) noexcept {}
        LampArrayColorRampEffect(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Lights::Effects::ILampArrayColorRampEffect(ptr, take_ownership_from_abi) {}
        LampArrayColorRampEffect(winrt::Windows::Devices::Lights::LampArray const& lampArray, array_view<int32_t const> lampIndexes);
    };
    struct __declspec(empty_bases) LampArrayCustomEffect : winrt::Windows::Devices::Lights::Effects::ILampArrayCustomEffect,
        impl::require<LampArrayCustomEffect, winrt::Windows::Devices::Lights::Effects::ILampArrayEffect>
    {
        LampArrayCustomEffect(std::nullptr_t) noexcept {}
        LampArrayCustomEffect(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Lights::Effects::ILampArrayCustomEffect(ptr, take_ownership_from_abi) {}
        LampArrayCustomEffect(winrt::Windows::Devices::Lights::LampArray const& lampArray, array_view<int32_t const> lampIndexes);
    };
    struct __declspec(empty_bases) LampArrayEffectPlaylist : winrt::Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist,
        impl::require<LampArrayEffectPlaylist, winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Devices::Lights::Effects::ILampArrayEffect>, winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Lights::Effects::ILampArrayEffect>>
    {
        LampArrayEffectPlaylist(std::nullptr_t) noexcept {}
        LampArrayEffectPlaylist(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Lights::Effects::ILampArrayEffectPlaylist(ptr, take_ownership_from_abi) {}
        LampArrayEffectPlaylist();
        static auto StartAll(param::iterable<winrt::Windows::Devices::Lights::Effects::LampArrayEffectPlaylist> const& value);
        static auto StopAll(param::iterable<winrt::Windows::Devices::Lights::Effects::LampArrayEffectPlaylist> const& value);
        static auto PauseAll(param::iterable<winrt::Windows::Devices::Lights::Effects::LampArrayEffectPlaylist> const& value);
    };
    struct __declspec(empty_bases) LampArraySolidEffect : winrt::Windows::Devices::Lights::Effects::ILampArraySolidEffect,
        impl::require<LampArraySolidEffect, winrt::Windows::Devices::Lights::Effects::ILampArrayEffect>
    {
        LampArraySolidEffect(std::nullptr_t) noexcept {}
        LampArraySolidEffect(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Lights::Effects::ILampArraySolidEffect(ptr, take_ownership_from_abi) {}
        LampArraySolidEffect(winrt::Windows::Devices::Lights::LampArray const& lampArray, array_view<int32_t const> lampIndexes);
    };
    struct __declspec(empty_bases) LampArrayUpdateRequestedEventArgs : winrt::Windows::Devices::Lights::Effects::ILampArrayUpdateRequestedEventArgs
    {
        LampArrayUpdateRequestedEventArgs(std::nullptr_t) noexcept {}
        LampArrayUpdateRequestedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Lights::Effects::ILampArrayUpdateRequestedEventArgs(ptr, take_ownership_from_abi) {}
    };
}
#endif
