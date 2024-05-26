// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Graphics_Holographic_1_H
#define WINRT_Windows_Graphics_Holographic_1_H
#include "winrt/impl/Windows.Foundation.0.h"
#include "winrt/impl/Windows.Graphics.Holographic.0.h"
WINRT_EXPORT namespace winrt::Windows::Graphics::Holographic
{
    struct __declspec(empty_bases) IHolographicCamera :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicCamera>
    {
        IHolographicCamera(std::nullptr_t = nullptr) noexcept {}
        IHolographicCamera(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicCamera2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicCamera2>,
        impl::require<winrt::Windows::Graphics::Holographic::IHolographicCamera2, winrt::Windows::Graphics::Holographic::IHolographicCamera>
    {
        IHolographicCamera2(std::nullptr_t = nullptr) noexcept {}
        IHolographicCamera2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicCamera3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicCamera3>,
        impl::require<winrt::Windows::Graphics::Holographic::IHolographicCamera3, winrt::Windows::Graphics::Holographic::IHolographicCamera, winrt::Windows::Graphics::Holographic::IHolographicCamera2>
    {
        IHolographicCamera3(std::nullptr_t = nullptr) noexcept {}
        IHolographicCamera3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicCamera4 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicCamera4>
    {
        IHolographicCamera4(std::nullptr_t = nullptr) noexcept {}
        IHolographicCamera4(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicCamera5 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicCamera5>
    {
        IHolographicCamera5(std::nullptr_t = nullptr) noexcept {}
        IHolographicCamera5(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicCamera6 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicCamera6>
    {
        IHolographicCamera6(std::nullptr_t = nullptr) noexcept {}
        IHolographicCamera6(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicCameraPose :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicCameraPose>
    {
        IHolographicCameraPose(std::nullptr_t = nullptr) noexcept {}
        IHolographicCameraPose(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicCameraPose2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicCameraPose2>
    {
        IHolographicCameraPose2(std::nullptr_t = nullptr) noexcept {}
        IHolographicCameraPose2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicCameraRenderingParameters :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicCameraRenderingParameters>
    {
        IHolographicCameraRenderingParameters(std::nullptr_t = nullptr) noexcept {}
        IHolographicCameraRenderingParameters(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicCameraRenderingParameters2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicCameraRenderingParameters2>,
        impl::require<winrt::Windows::Graphics::Holographic::IHolographicCameraRenderingParameters2, winrt::Windows::Graphics::Holographic::IHolographicCameraRenderingParameters>
    {
        IHolographicCameraRenderingParameters2(std::nullptr_t = nullptr) noexcept {}
        IHolographicCameraRenderingParameters2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicCameraRenderingParameters3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicCameraRenderingParameters3>,
        impl::require<winrt::Windows::Graphics::Holographic::IHolographicCameraRenderingParameters3, winrt::Windows::Graphics::Holographic::IHolographicCameraRenderingParameters, winrt::Windows::Graphics::Holographic::IHolographicCameraRenderingParameters2>
    {
        IHolographicCameraRenderingParameters3(std::nullptr_t = nullptr) noexcept {}
        IHolographicCameraRenderingParameters3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicCameraRenderingParameters4 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicCameraRenderingParameters4>
    {
        IHolographicCameraRenderingParameters4(std::nullptr_t = nullptr) noexcept {}
        IHolographicCameraRenderingParameters4(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicCameraViewportParameters :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicCameraViewportParameters>
    {
        IHolographicCameraViewportParameters(std::nullptr_t = nullptr) noexcept {}
        IHolographicCameraViewportParameters(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicDisplay :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicDisplay>
    {
        IHolographicDisplay(std::nullptr_t = nullptr) noexcept {}
        IHolographicDisplay(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicDisplay2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicDisplay2>
    {
        IHolographicDisplay2(std::nullptr_t = nullptr) noexcept {}
        IHolographicDisplay2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicDisplay3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicDisplay3>
    {
        IHolographicDisplay3(std::nullptr_t = nullptr) noexcept {}
        IHolographicDisplay3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicDisplayStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicDisplayStatics>
    {
        IHolographicDisplayStatics(std::nullptr_t = nullptr) noexcept {}
        IHolographicDisplayStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicFrame :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicFrame>
    {
        IHolographicFrame(std::nullptr_t = nullptr) noexcept {}
        IHolographicFrame(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicFrame2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicFrame2>,
        impl::require<winrt::Windows::Graphics::Holographic::IHolographicFrame2, winrt::Windows::Graphics::Holographic::IHolographicFrame>
    {
        IHolographicFrame2(std::nullptr_t = nullptr) noexcept {}
        IHolographicFrame2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicFrame3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicFrame3>
    {
        IHolographicFrame3(std::nullptr_t = nullptr) noexcept {}
        IHolographicFrame3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicFramePrediction :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicFramePrediction>
    {
        IHolographicFramePrediction(std::nullptr_t = nullptr) noexcept {}
        IHolographicFramePrediction(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicFramePresentationMonitor :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicFramePresentationMonitor>,
        impl::require<winrt::Windows::Graphics::Holographic::IHolographicFramePresentationMonitor, winrt::Windows::Foundation::IClosable>
    {
        IHolographicFramePresentationMonitor(std::nullptr_t = nullptr) noexcept {}
        IHolographicFramePresentationMonitor(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicFramePresentationReport :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicFramePresentationReport>
    {
        IHolographicFramePresentationReport(std::nullptr_t = nullptr) noexcept {}
        IHolographicFramePresentationReport(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicFrameRenderingReport :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicFrameRenderingReport>
    {
        IHolographicFrameRenderingReport(std::nullptr_t = nullptr) noexcept {}
        IHolographicFrameRenderingReport(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicFrameScanoutMonitor :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicFrameScanoutMonitor>,
        impl::require<winrt::Windows::Graphics::Holographic::IHolographicFrameScanoutMonitor, winrt::Windows::Foundation::IClosable>
    {
        IHolographicFrameScanoutMonitor(std::nullptr_t = nullptr) noexcept {}
        IHolographicFrameScanoutMonitor(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicFrameScanoutReport :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicFrameScanoutReport>
    {
        IHolographicFrameScanoutReport(std::nullptr_t = nullptr) noexcept {}
        IHolographicFrameScanoutReport(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicQuadLayer :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicQuadLayer>
    {
        IHolographicQuadLayer(std::nullptr_t = nullptr) noexcept {}
        IHolographicQuadLayer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicQuadLayerFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicQuadLayerFactory>
    {
        IHolographicQuadLayerFactory(std::nullptr_t = nullptr) noexcept {}
        IHolographicQuadLayerFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicQuadLayerUpdateParameters :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicQuadLayerUpdateParameters>
    {
        IHolographicQuadLayerUpdateParameters(std::nullptr_t = nullptr) noexcept {}
        IHolographicQuadLayerUpdateParameters(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicQuadLayerUpdateParameters2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicQuadLayerUpdateParameters2>
    {
        IHolographicQuadLayerUpdateParameters2(std::nullptr_t = nullptr) noexcept {}
        IHolographicQuadLayerUpdateParameters2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicSpace :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicSpace>
    {
        IHolographicSpace(std::nullptr_t = nullptr) noexcept {}
        IHolographicSpace(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicSpace2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicSpace2>
    {
        IHolographicSpace2(std::nullptr_t = nullptr) noexcept {}
        IHolographicSpace2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicSpace3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicSpace3>
    {
        IHolographicSpace3(std::nullptr_t = nullptr) noexcept {}
        IHolographicSpace3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicSpaceCameraAddedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicSpaceCameraAddedEventArgs>
    {
        IHolographicSpaceCameraAddedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IHolographicSpaceCameraAddedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicSpaceCameraRemovedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicSpaceCameraRemovedEventArgs>
    {
        IHolographicSpaceCameraRemovedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IHolographicSpaceCameraRemovedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicSpaceStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicSpaceStatics>
    {
        IHolographicSpaceStatics(std::nullptr_t = nullptr) noexcept {}
        IHolographicSpaceStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicSpaceStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicSpaceStatics2>
    {
        IHolographicSpaceStatics2(std::nullptr_t = nullptr) noexcept {}
        IHolographicSpaceStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicSpaceStatics3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicSpaceStatics3>
    {
        IHolographicSpaceStatics3(std::nullptr_t = nullptr) noexcept {}
        IHolographicSpaceStatics3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicViewConfiguration :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicViewConfiguration>
    {
        IHolographicViewConfiguration(std::nullptr_t = nullptr) noexcept {}
        IHolographicViewConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IHolographicViewConfiguration2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IHolographicViewConfiguration2>
    {
        IHolographicViewConfiguration2(std::nullptr_t = nullptr) noexcept {}
        IHolographicViewConfiguration2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
