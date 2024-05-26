// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Perception_2_H
#define WINRT_Windows_Devices_Perception_2_H
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Devices.Perception.1.h"
WINRT_EXPORT namespace winrt::Windows::Devices::Perception
{
    struct KnownCameraIntrinsicsProperties
    {
        KnownCameraIntrinsicsProperties() = delete;
        [[nodiscard]] static auto FocalLength();
        [[nodiscard]] static auto PrincipalPoint();
        [[nodiscard]] static auto RadialDistortion();
        [[nodiscard]] static auto TangentialDistortion();
    };
    struct KnownPerceptionColorFrameSourceProperties
    {
        KnownPerceptionColorFrameSourceProperties() = delete;
        [[nodiscard]] static auto Exposure();
        [[nodiscard]] static auto AutoExposureEnabled();
        [[nodiscard]] static auto ExposureCompensation();
    };
    struct KnownPerceptionDepthFrameSourceProperties
    {
        KnownPerceptionDepthFrameSourceProperties() = delete;
        [[nodiscard]] static auto MinDepth();
        [[nodiscard]] static auto MaxDepth();
    };
    struct KnownPerceptionFrameSourceProperties
    {
        KnownPerceptionFrameSourceProperties() = delete;
        [[nodiscard]] static auto Id();
        [[nodiscard]] static auto PhysicalDeviceIds();
        [[nodiscard]] static auto FrameKind();
        [[nodiscard]] static auto DeviceModelVersion();
        [[nodiscard]] static auto EnclosureLocation();
        [[nodiscard]] static auto DeviceId();
    };
    struct KnownPerceptionInfraredFrameSourceProperties
    {
        KnownPerceptionInfraredFrameSourceProperties() = delete;
        [[nodiscard]] static auto Exposure();
        [[nodiscard]] static auto AutoExposureEnabled();
        [[nodiscard]] static auto ExposureCompensation();
        [[nodiscard]] static auto ActiveIlluminationEnabled();
        [[nodiscard]] static auto AmbientSubtractionEnabled();
        [[nodiscard]] static auto StructureLightPatternEnabled();
        [[nodiscard]] static auto InterleavedIlluminationEnabled();
    };
    struct KnownPerceptionVideoFrameSourceProperties
    {
        KnownPerceptionVideoFrameSourceProperties() = delete;
        [[nodiscard]] static auto VideoProfile();
        [[nodiscard]] static auto SupportedVideoProfiles();
        [[nodiscard]] static auto AvailableVideoProfiles();
        [[nodiscard]] static auto IsMirrored();
        [[nodiscard]] static auto CameraIntrinsics();
    };
    struct KnownPerceptionVideoProfileProperties
    {
        KnownPerceptionVideoProfileProperties() = delete;
        [[nodiscard]] static auto BitmapPixelFormat();
        [[nodiscard]] static auto BitmapAlphaMode();
        [[nodiscard]] static auto Width();
        [[nodiscard]] static auto Height();
        [[nodiscard]] static auto FrameDuration();
    };
    struct __declspec(empty_bases) PerceptionColorFrame : winrt::Windows::Devices::Perception::IPerceptionColorFrame
    {
        PerceptionColorFrame(std::nullptr_t) noexcept {}
        PerceptionColorFrame(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Perception::IPerceptionColorFrame(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PerceptionColorFrameArrivedEventArgs : winrt::Windows::Devices::Perception::IPerceptionColorFrameArrivedEventArgs
    {
        PerceptionColorFrameArrivedEventArgs(std::nullptr_t) noexcept {}
        PerceptionColorFrameArrivedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Perception::IPerceptionColorFrameArrivedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PerceptionColorFrameReader : winrt::Windows::Devices::Perception::IPerceptionColorFrameReader
    {
        PerceptionColorFrameReader(std::nullptr_t) noexcept {}
        PerceptionColorFrameReader(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Perception::IPerceptionColorFrameReader(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PerceptionColorFrameSource : winrt::Windows::Devices::Perception::IPerceptionColorFrameSource,
        impl::require<PerceptionColorFrameSource, winrt::Windows::Devices::Perception::IPerceptionColorFrameSource2>
    {
        PerceptionColorFrameSource(std::nullptr_t) noexcept {}
        PerceptionColorFrameSource(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Perception::IPerceptionColorFrameSource(ptr, take_ownership_from_abi) {}
        static auto CreateWatcher();
        static auto FindAllAsync();
        static auto FromIdAsync(param::hstring const& id);
        static auto RequestAccessAsync();
    };
    struct __declspec(empty_bases) PerceptionColorFrameSourceAddedEventArgs : winrt::Windows::Devices::Perception::IPerceptionColorFrameSourceAddedEventArgs
    {
        PerceptionColorFrameSourceAddedEventArgs(std::nullptr_t) noexcept {}
        PerceptionColorFrameSourceAddedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Perception::IPerceptionColorFrameSourceAddedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PerceptionColorFrameSourceRemovedEventArgs : winrt::Windows::Devices::Perception::IPerceptionColorFrameSourceRemovedEventArgs
    {
        PerceptionColorFrameSourceRemovedEventArgs(std::nullptr_t) noexcept {}
        PerceptionColorFrameSourceRemovedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Perception::IPerceptionColorFrameSourceRemovedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PerceptionColorFrameSourceWatcher : winrt::Windows::Devices::Perception::IPerceptionColorFrameSourceWatcher
    {
        PerceptionColorFrameSourceWatcher(std::nullptr_t) noexcept {}
        PerceptionColorFrameSourceWatcher(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Perception::IPerceptionColorFrameSourceWatcher(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PerceptionControlSession : winrt::Windows::Devices::Perception::IPerceptionControlSession
    {
        PerceptionControlSession(std::nullptr_t) noexcept {}
        PerceptionControlSession(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Perception::IPerceptionControlSession(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PerceptionDepthCorrelatedCameraIntrinsics : winrt::Windows::Devices::Perception::IPerceptionDepthCorrelatedCameraIntrinsics
    {
        PerceptionDepthCorrelatedCameraIntrinsics(std::nullptr_t) noexcept {}
        PerceptionDepthCorrelatedCameraIntrinsics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Perception::IPerceptionDepthCorrelatedCameraIntrinsics(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PerceptionDepthCorrelatedCoordinateMapper : winrt::Windows::Devices::Perception::IPerceptionDepthCorrelatedCoordinateMapper
    {
        PerceptionDepthCorrelatedCoordinateMapper(std::nullptr_t) noexcept {}
        PerceptionDepthCorrelatedCoordinateMapper(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Perception::IPerceptionDepthCorrelatedCoordinateMapper(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PerceptionDepthFrame : winrt::Windows::Devices::Perception::IPerceptionDepthFrame
    {
        PerceptionDepthFrame(std::nullptr_t) noexcept {}
        PerceptionDepthFrame(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Perception::IPerceptionDepthFrame(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PerceptionDepthFrameArrivedEventArgs : winrt::Windows::Devices::Perception::IPerceptionDepthFrameArrivedEventArgs
    {
        PerceptionDepthFrameArrivedEventArgs(std::nullptr_t) noexcept {}
        PerceptionDepthFrameArrivedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Perception::IPerceptionDepthFrameArrivedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PerceptionDepthFrameReader : winrt::Windows::Devices::Perception::IPerceptionDepthFrameReader
    {
        PerceptionDepthFrameReader(std::nullptr_t) noexcept {}
        PerceptionDepthFrameReader(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Perception::IPerceptionDepthFrameReader(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PerceptionDepthFrameSource : winrt::Windows::Devices::Perception::IPerceptionDepthFrameSource,
        impl::require<PerceptionDepthFrameSource, winrt::Windows::Devices::Perception::IPerceptionDepthFrameSource2>
    {
        PerceptionDepthFrameSource(std::nullptr_t) noexcept {}
        PerceptionDepthFrameSource(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Perception::IPerceptionDepthFrameSource(ptr, take_ownership_from_abi) {}
        static auto CreateWatcher();
        static auto FindAllAsync();
        static auto FromIdAsync(param::hstring const& id);
        static auto RequestAccessAsync();
    };
    struct __declspec(empty_bases) PerceptionDepthFrameSourceAddedEventArgs : winrt::Windows::Devices::Perception::IPerceptionDepthFrameSourceAddedEventArgs
    {
        PerceptionDepthFrameSourceAddedEventArgs(std::nullptr_t) noexcept {}
        PerceptionDepthFrameSourceAddedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Perception::IPerceptionDepthFrameSourceAddedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PerceptionDepthFrameSourceRemovedEventArgs : winrt::Windows::Devices::Perception::IPerceptionDepthFrameSourceRemovedEventArgs
    {
        PerceptionDepthFrameSourceRemovedEventArgs(std::nullptr_t) noexcept {}
        PerceptionDepthFrameSourceRemovedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Perception::IPerceptionDepthFrameSourceRemovedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PerceptionDepthFrameSourceWatcher : winrt::Windows::Devices::Perception::IPerceptionDepthFrameSourceWatcher
    {
        PerceptionDepthFrameSourceWatcher(std::nullptr_t) noexcept {}
        PerceptionDepthFrameSourceWatcher(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Perception::IPerceptionDepthFrameSourceWatcher(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PerceptionFrameSourcePropertiesChangedEventArgs : winrt::Windows::Devices::Perception::IPerceptionFrameSourcePropertiesChangedEventArgs
    {
        PerceptionFrameSourcePropertiesChangedEventArgs(std::nullptr_t) noexcept {}
        PerceptionFrameSourcePropertiesChangedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Perception::IPerceptionFrameSourcePropertiesChangedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PerceptionFrameSourcePropertyChangeResult : winrt::Windows::Devices::Perception::IPerceptionFrameSourcePropertyChangeResult
    {
        PerceptionFrameSourcePropertyChangeResult(std::nullptr_t) noexcept {}
        PerceptionFrameSourcePropertyChangeResult(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Perception::IPerceptionFrameSourcePropertyChangeResult(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PerceptionInfraredFrame : winrt::Windows::Devices::Perception::IPerceptionInfraredFrame
    {
        PerceptionInfraredFrame(std::nullptr_t) noexcept {}
        PerceptionInfraredFrame(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Perception::IPerceptionInfraredFrame(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PerceptionInfraredFrameArrivedEventArgs : winrt::Windows::Devices::Perception::IPerceptionInfraredFrameArrivedEventArgs
    {
        PerceptionInfraredFrameArrivedEventArgs(std::nullptr_t) noexcept {}
        PerceptionInfraredFrameArrivedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Perception::IPerceptionInfraredFrameArrivedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PerceptionInfraredFrameReader : winrt::Windows::Devices::Perception::IPerceptionInfraredFrameReader
    {
        PerceptionInfraredFrameReader(std::nullptr_t) noexcept {}
        PerceptionInfraredFrameReader(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Perception::IPerceptionInfraredFrameReader(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PerceptionInfraredFrameSource : winrt::Windows::Devices::Perception::IPerceptionInfraredFrameSource,
        impl::require<PerceptionInfraredFrameSource, winrt::Windows::Devices::Perception::IPerceptionInfraredFrameSource2>
    {
        PerceptionInfraredFrameSource(std::nullptr_t) noexcept {}
        PerceptionInfraredFrameSource(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Perception::IPerceptionInfraredFrameSource(ptr, take_ownership_from_abi) {}
        static auto CreateWatcher();
        static auto FindAllAsync();
        static auto FromIdAsync(param::hstring const& id);
        static auto RequestAccessAsync();
    };
    struct __declspec(empty_bases) PerceptionInfraredFrameSourceAddedEventArgs : winrt::Windows::Devices::Perception::IPerceptionInfraredFrameSourceAddedEventArgs
    {
        PerceptionInfraredFrameSourceAddedEventArgs(std::nullptr_t) noexcept {}
        PerceptionInfraredFrameSourceAddedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Perception::IPerceptionInfraredFrameSourceAddedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PerceptionInfraredFrameSourceRemovedEventArgs : winrt::Windows::Devices::Perception::IPerceptionInfraredFrameSourceRemovedEventArgs
    {
        PerceptionInfraredFrameSourceRemovedEventArgs(std::nullptr_t) noexcept {}
        PerceptionInfraredFrameSourceRemovedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Perception::IPerceptionInfraredFrameSourceRemovedEventArgs(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PerceptionInfraredFrameSourceWatcher : winrt::Windows::Devices::Perception::IPerceptionInfraredFrameSourceWatcher
    {
        PerceptionInfraredFrameSourceWatcher(std::nullptr_t) noexcept {}
        PerceptionInfraredFrameSourceWatcher(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Perception::IPerceptionInfraredFrameSourceWatcher(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) PerceptionVideoProfile : winrt::Windows::Devices::Perception::IPerceptionVideoProfile
    {
        PerceptionVideoProfile(std::nullptr_t) noexcept {}
        PerceptionVideoProfile(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Devices::Perception::IPerceptionVideoProfile(ptr, take_ownership_from_abi) {}
    };
}
#endif
