// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_Devices_Core_2_H
#define WINRT_Windows_Media_Devices_Core_2_H
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Foundation.Numerics.1.h"
#include "winrt/impl/Windows.Media.Devices.Core.1.h"
WINRT_EXPORT namespace winrt::Windows::Media::Devices::Core
{
    struct __declspec(empty_bases) CameraIntrinsics : winrt::Windows::Media::Devices::Core::ICameraIntrinsics,
        impl::require<CameraIntrinsics, winrt::Windows::Media::Devices::Core::ICameraIntrinsics2>
    {
        CameraIntrinsics(std::nullptr_t) noexcept {}
        CameraIntrinsics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Devices::Core::ICameraIntrinsics(ptr, take_ownership_from_abi) {}
        CameraIntrinsics(winrt::Windows::Foundation::Numerics::float2 const& focalLength, winrt::Windows::Foundation::Numerics::float2 const& principalPoint, winrt::Windows::Foundation::Numerics::float3 const& radialDistortion, winrt::Windows::Foundation::Numerics::float2 const& tangentialDistortion, uint32_t imageWidth, uint32_t imageHeight);
    };
    struct __declspec(empty_bases) DepthCorrelatedCoordinateMapper : winrt::Windows::Media::Devices::Core::IDepthCorrelatedCoordinateMapper
    {
        DepthCorrelatedCoordinateMapper(std::nullptr_t) noexcept {}
        DepthCorrelatedCoordinateMapper(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Devices::Core::IDepthCorrelatedCoordinateMapper(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) FrameControlCapabilities : winrt::Windows::Media::Devices::Core::IFrameControlCapabilities,
        impl::require<FrameControlCapabilities, winrt::Windows::Media::Devices::Core::IFrameControlCapabilities2>
    {
        FrameControlCapabilities(std::nullptr_t) noexcept {}
        FrameControlCapabilities(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Devices::Core::IFrameControlCapabilities(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) FrameController : winrt::Windows::Media::Devices::Core::IFrameController,
        impl::require<FrameController, winrt::Windows::Media::Devices::Core::IFrameController2>
    {
        FrameController(std::nullptr_t) noexcept {}
        FrameController(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Devices::Core::IFrameController(ptr, take_ownership_from_abi) {}
        FrameController();
    };
    struct __declspec(empty_bases) FrameExposureCapabilities : winrt::Windows::Media::Devices::Core::IFrameExposureCapabilities
    {
        FrameExposureCapabilities(std::nullptr_t) noexcept {}
        FrameExposureCapabilities(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Devices::Core::IFrameExposureCapabilities(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) FrameExposureCompensationCapabilities : winrt::Windows::Media::Devices::Core::IFrameExposureCompensationCapabilities
    {
        FrameExposureCompensationCapabilities(std::nullptr_t) noexcept {}
        FrameExposureCompensationCapabilities(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Devices::Core::IFrameExposureCompensationCapabilities(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) FrameExposureCompensationControl : winrt::Windows::Media::Devices::Core::IFrameExposureCompensationControl
    {
        FrameExposureCompensationControl(std::nullptr_t) noexcept {}
        FrameExposureCompensationControl(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Devices::Core::IFrameExposureCompensationControl(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) FrameExposureControl : winrt::Windows::Media::Devices::Core::IFrameExposureControl
    {
        FrameExposureControl(std::nullptr_t) noexcept {}
        FrameExposureControl(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Devices::Core::IFrameExposureControl(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) FrameFlashCapabilities : winrt::Windows::Media::Devices::Core::IFrameFlashCapabilities
    {
        FrameFlashCapabilities(std::nullptr_t) noexcept {}
        FrameFlashCapabilities(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Devices::Core::IFrameFlashCapabilities(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) FrameFlashControl : winrt::Windows::Media::Devices::Core::IFrameFlashControl
    {
        FrameFlashControl(std::nullptr_t) noexcept {}
        FrameFlashControl(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Devices::Core::IFrameFlashControl(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) FrameFocusCapabilities : winrt::Windows::Media::Devices::Core::IFrameFocusCapabilities
    {
        FrameFocusCapabilities(std::nullptr_t) noexcept {}
        FrameFocusCapabilities(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Devices::Core::IFrameFocusCapabilities(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) FrameFocusControl : winrt::Windows::Media::Devices::Core::IFrameFocusControl
    {
        FrameFocusControl(std::nullptr_t) noexcept {}
        FrameFocusControl(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Devices::Core::IFrameFocusControl(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) FrameIsoSpeedCapabilities : winrt::Windows::Media::Devices::Core::IFrameIsoSpeedCapabilities
    {
        FrameIsoSpeedCapabilities(std::nullptr_t) noexcept {}
        FrameIsoSpeedCapabilities(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Devices::Core::IFrameIsoSpeedCapabilities(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) FrameIsoSpeedControl : winrt::Windows::Media::Devices::Core::IFrameIsoSpeedControl
    {
        FrameIsoSpeedControl(std::nullptr_t) noexcept {}
        FrameIsoSpeedControl(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Devices::Core::IFrameIsoSpeedControl(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) VariablePhotoSequenceController : winrt::Windows::Media::Devices::Core::IVariablePhotoSequenceController
    {
        VariablePhotoSequenceController(std::nullptr_t) noexcept {}
        VariablePhotoSequenceController(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Media::Devices::Core::IVariablePhotoSequenceController(ptr, take_ownership_from_abi) {}
    };
}
#endif
