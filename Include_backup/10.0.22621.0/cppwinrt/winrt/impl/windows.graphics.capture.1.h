// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Graphics_Capture_1_H
#define WINRT_Windows_Graphics_Capture_1_H
#include "winrt/impl/Windows.Graphics.Capture.0.h"
WINRT_EXPORT namespace winrt::Windows::Graphics::Capture
{
    struct __declspec(empty_bases) IDirect3D11CaptureFrame :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDirect3D11CaptureFrame>
    {
        IDirect3D11CaptureFrame(std::nullptr_t = nullptr) noexcept {}
        IDirect3D11CaptureFrame(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDirect3D11CaptureFramePool :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDirect3D11CaptureFramePool>
    {
        IDirect3D11CaptureFramePool(std::nullptr_t = nullptr) noexcept {}
        IDirect3D11CaptureFramePool(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDirect3D11CaptureFramePoolStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDirect3D11CaptureFramePoolStatics>
    {
        IDirect3D11CaptureFramePoolStatics(std::nullptr_t = nullptr) noexcept {}
        IDirect3D11CaptureFramePoolStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDirect3D11CaptureFramePoolStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDirect3D11CaptureFramePoolStatics2>
    {
        IDirect3D11CaptureFramePoolStatics2(std::nullptr_t = nullptr) noexcept {}
        IDirect3D11CaptureFramePoolStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGraphicsCaptureAccessStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGraphicsCaptureAccessStatics>
    {
        IGraphicsCaptureAccessStatics(std::nullptr_t = nullptr) noexcept {}
        IGraphicsCaptureAccessStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGraphicsCaptureItem :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGraphicsCaptureItem>
    {
        IGraphicsCaptureItem(std::nullptr_t = nullptr) noexcept {}
        IGraphicsCaptureItem(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGraphicsCaptureItemStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGraphicsCaptureItemStatics>
    {
        IGraphicsCaptureItemStatics(std::nullptr_t = nullptr) noexcept {}
        IGraphicsCaptureItemStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGraphicsCaptureItemStatics2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGraphicsCaptureItemStatics2>
    {
        IGraphicsCaptureItemStatics2(std::nullptr_t = nullptr) noexcept {}
        IGraphicsCaptureItemStatics2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGraphicsCapturePicker :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGraphicsCapturePicker>
    {
        IGraphicsCapturePicker(std::nullptr_t = nullptr) noexcept {}
        IGraphicsCapturePicker(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGraphicsCaptureSession :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGraphicsCaptureSession>
    {
        IGraphicsCaptureSession(std::nullptr_t = nullptr) noexcept {}
        IGraphicsCaptureSession(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGraphicsCaptureSession2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGraphicsCaptureSession2>
    {
        IGraphicsCaptureSession2(std::nullptr_t = nullptr) noexcept {}
        IGraphicsCaptureSession2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGraphicsCaptureSession3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGraphicsCaptureSession3>
    {
        IGraphicsCaptureSession3(std::nullptr_t = nullptr) noexcept {}
        IGraphicsCaptureSession3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IGraphicsCaptureSessionStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IGraphicsCaptureSessionStatics>
    {
        IGraphicsCaptureSessionStatics(std::nullptr_t = nullptr) noexcept {}
        IGraphicsCaptureSessionStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
