// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Graphics_Capture_2_H
#define WINRT_Windows_Graphics_Capture_2_H
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Graphics.1.h"
#include "winrt/impl/Windows.Graphics.DirectX.1.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.1.h"
#include "winrt/impl/Windows.UI.1.h"
#include "winrt/impl/Windows.UI.Composition.1.h"
#include "winrt/impl/Windows.Graphics.Capture.1.h"
WINRT_EXPORT namespace winrt::Windows::Graphics::Capture
{
    struct __declspec(empty_bases) Direct3D11CaptureFrame : winrt::Windows::Graphics::Capture::IDirect3D11CaptureFrame,
        impl::require<Direct3D11CaptureFrame, winrt::Windows::Foundation::IClosable>
    {
        Direct3D11CaptureFrame(std::nullptr_t) noexcept {}
        Direct3D11CaptureFrame(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Graphics::Capture::IDirect3D11CaptureFrame(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) Direct3D11CaptureFramePool : winrt::Windows::Graphics::Capture::IDirect3D11CaptureFramePool,
        impl::require<Direct3D11CaptureFramePool, winrt::Windows::Foundation::IClosable>
    {
        Direct3D11CaptureFramePool(std::nullptr_t) noexcept {}
        Direct3D11CaptureFramePool(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Graphics::Capture::IDirect3D11CaptureFramePool(ptr, take_ownership_from_abi) {}
        static auto Create(winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device, winrt::Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, int32_t numberOfBuffers, winrt::Windows::Graphics::SizeInt32 const& size);
        static auto CreateFreeThreaded(winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device, winrt::Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, int32_t numberOfBuffers, winrt::Windows::Graphics::SizeInt32 const& size);
    };
    struct GraphicsCaptureAccess
    {
        GraphicsCaptureAccess() = delete;
        static auto RequestAccessAsync(winrt::Windows::Graphics::Capture::GraphicsCaptureAccessKind const& request);
    };
    struct __declspec(empty_bases) GraphicsCaptureItem : winrt::Windows::Graphics::Capture::IGraphicsCaptureItem
    {
        GraphicsCaptureItem(std::nullptr_t) noexcept {}
        GraphicsCaptureItem(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Graphics::Capture::IGraphicsCaptureItem(ptr, take_ownership_from_abi) {}
        static auto CreateFromVisual(winrt::Windows::UI::Composition::Visual const& visual);
        static auto TryCreateFromWindowId(winrt::Windows::UI::WindowId const& windowId);
        static auto TryCreateFromDisplayId(winrt::Windows::Graphics::DisplayId const& displayId);
    };
    struct __declspec(empty_bases) GraphicsCapturePicker : winrt::Windows::Graphics::Capture::IGraphicsCapturePicker
    {
        GraphicsCapturePicker(std::nullptr_t) noexcept {}
        GraphicsCapturePicker(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Graphics::Capture::IGraphicsCapturePicker(ptr, take_ownership_from_abi) {}
        GraphicsCapturePicker();
    };
    struct __declspec(empty_bases) GraphicsCaptureSession : winrt::Windows::Graphics::Capture::IGraphicsCaptureSession,
        impl::require<GraphicsCaptureSession, winrt::Windows::Graphics::Capture::IGraphicsCaptureSession2, winrt::Windows::Graphics::Capture::IGraphicsCaptureSession3, winrt::Windows::Foundation::IClosable>
    {
        GraphicsCaptureSession(std::nullptr_t) noexcept {}
        GraphicsCaptureSession(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Graphics::Capture::IGraphicsCaptureSession(ptr, take_ownership_from_abi) {}
        static auto IsSupported();
    };
}
#endif
