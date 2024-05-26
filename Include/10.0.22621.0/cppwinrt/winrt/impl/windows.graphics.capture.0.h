// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Graphics_Capture_0_H
#define WINRT_Windows_Graphics_Capture_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct EventRegistrationToken;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
}
WINRT_EXPORT namespace winrt::Windows::Graphics
{
    struct DisplayId;
    struct SizeInt32;
}
WINRT_EXPORT namespace winrt::Windows::Graphics::DirectX
{
    enum class DirectXPixelFormat : int32_t;
}
WINRT_EXPORT namespace winrt::Windows::Graphics::DirectX::Direct3D11
{
    struct IDirect3DDevice;
    struct IDirect3DSurface;
}
WINRT_EXPORT namespace winrt::Windows::Security::Authorization::AppCapabilityAccess
{
    enum class AppCapabilityAccessStatus : int32_t;
}
WINRT_EXPORT namespace winrt::Windows::System
{
    struct DispatcherQueue;
}
WINRT_EXPORT namespace winrt::Windows::UI
{
    struct WindowId;
}
WINRT_EXPORT namespace winrt::Windows::UI::Composition
{
    struct Visual;
}
WINRT_EXPORT namespace winrt::Windows::Graphics::Capture
{
    enum class GraphicsCaptureAccessKind : int32_t
    {
        Borderless = 0,
        Programmatic = 1,
    };
    struct IDirect3D11CaptureFrame;
    struct IDirect3D11CaptureFramePool;
    struct IDirect3D11CaptureFramePoolStatics;
    struct IDirect3D11CaptureFramePoolStatics2;
    struct IGraphicsCaptureAccessStatics;
    struct IGraphicsCaptureItem;
    struct IGraphicsCaptureItemStatics;
    struct IGraphicsCaptureItemStatics2;
    struct IGraphicsCapturePicker;
    struct IGraphicsCaptureSession;
    struct IGraphicsCaptureSession2;
    struct IGraphicsCaptureSession3;
    struct IGraphicsCaptureSessionStatics;
    struct Direct3D11CaptureFrame;
    struct Direct3D11CaptureFramePool;
    struct GraphicsCaptureAccess;
    struct GraphicsCaptureItem;
    struct GraphicsCapturePicker;
    struct GraphicsCaptureSession;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFrame>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFramePool>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Capture::IGraphicsCaptureAccessStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Capture::IGraphicsCaptureItem>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Capture::IGraphicsCaptureItemStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Capture::IGraphicsCaptureItemStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Capture::IGraphicsCapturePicker>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Capture::IGraphicsCaptureSession>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Capture::IGraphicsCaptureSession2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Capture::IGraphicsCaptureSession3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Capture::IGraphicsCaptureSessionStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Graphics::Capture::Direct3D11CaptureFrame>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Capture::Direct3D11CaptureFramePool>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Capture::GraphicsCaptureAccess>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Capture::GraphicsCaptureItem>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Capture::GraphicsCapturePicker>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Capture::GraphicsCaptureSession>{ using type = class_category; };
    template <> struct category<winrt::Windows::Graphics::Capture::GraphicsCaptureAccessKind>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Capture::Direct3D11CaptureFrame> = L"Windows.Graphics.Capture.Direct3D11CaptureFrame";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Capture::Direct3D11CaptureFramePool> = L"Windows.Graphics.Capture.Direct3D11CaptureFramePool";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Capture::GraphicsCaptureAccess> = L"Windows.Graphics.Capture.GraphicsCaptureAccess";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Capture::GraphicsCaptureItem> = L"Windows.Graphics.Capture.GraphicsCaptureItem";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Capture::GraphicsCapturePicker> = L"Windows.Graphics.Capture.GraphicsCapturePicker";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Capture::GraphicsCaptureSession> = L"Windows.Graphics.Capture.GraphicsCaptureSession";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Capture::GraphicsCaptureAccessKind> = L"Windows.Graphics.Capture.GraphicsCaptureAccessKind";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFrame> = L"Windows.Graphics.Capture.IDirect3D11CaptureFrame";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFramePool> = L"Windows.Graphics.Capture.IDirect3D11CaptureFramePool";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics> = L"Windows.Graphics.Capture.IDirect3D11CaptureFramePoolStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics2> = L"Windows.Graphics.Capture.IDirect3D11CaptureFramePoolStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Capture::IGraphicsCaptureAccessStatics> = L"Windows.Graphics.Capture.IGraphicsCaptureAccessStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Capture::IGraphicsCaptureItem> = L"Windows.Graphics.Capture.IGraphicsCaptureItem";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Capture::IGraphicsCaptureItemStatics> = L"Windows.Graphics.Capture.IGraphicsCaptureItemStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Capture::IGraphicsCaptureItemStatics2> = L"Windows.Graphics.Capture.IGraphicsCaptureItemStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Capture::IGraphicsCapturePicker> = L"Windows.Graphics.Capture.IGraphicsCapturePicker";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Capture::IGraphicsCaptureSession> = L"Windows.Graphics.Capture.IGraphicsCaptureSession";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Capture::IGraphicsCaptureSession2> = L"Windows.Graphics.Capture.IGraphicsCaptureSession2";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Capture::IGraphicsCaptureSession3> = L"Windows.Graphics.Capture.IGraphicsCaptureSession3";
    template <> inline constexpr auto& name_v<winrt::Windows::Graphics::Capture::IGraphicsCaptureSessionStatics> = L"Windows.Graphics.Capture.IGraphicsCaptureSessionStatics";
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFrame>{ 0xFA50C623,0x38DA,0x4B32,{ 0xAC,0xF3,0xFA,0x97,0x34,0xAD,0x80,0x0E } }; // FA50C623-38DA-4B32-ACF3-FA9734AD800E
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFramePool>{ 0x24EB6D22,0x1975,0x422E,{ 0x82,0xE7,0x78,0x0D,0xBD,0x8D,0xDF,0x24 } }; // 24EB6D22-1975-422E-82E7-780DBD8DDF24
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics>{ 0x7784056A,0x67AA,0x4D53,{ 0xAE,0x54,0x10,0x88,0xD5,0xA8,0xCA,0x21 } }; // 7784056A-67AA-4D53-AE54-1088D5A8CA21
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics2>{ 0x589B103F,0x6BBC,0x5DF5,{ 0xA9,0x91,0x02,0xE2,0x8B,0x3B,0x66,0xD5 } }; // 589B103F-6BBC-5DF5-A991-02E28B3B66D5
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Capture::IGraphicsCaptureAccessStatics>{ 0x743ED370,0x06EC,0x5040,{ 0xA5,0x8A,0x90,0x1F,0x0F,0x75,0x70,0x95 } }; // 743ED370-06EC-5040-A58A-901F0F757095
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Capture::IGraphicsCaptureItem>{ 0x79C3F95B,0x31F7,0x4EC2,{ 0xA4,0x64,0x63,0x2E,0xF5,0xD3,0x07,0x60 } }; // 79C3F95B-31F7-4EC2-A464-632EF5D30760
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Capture::IGraphicsCaptureItemStatics>{ 0xA87EBEA5,0x457C,0x5788,{ 0xAB,0x47,0x0C,0xF1,0xD3,0x63,0x7E,0x74 } }; // A87EBEA5-457C-5788-AB47-0CF1D3637E74
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Capture::IGraphicsCaptureItemStatics2>{ 0x3B92ACC9,0xE584,0x5862,{ 0xBF,0x5C,0x9C,0x31,0x6C,0x6D,0x2D,0xBB } }; // 3B92ACC9-E584-5862-BF5C-9C316C6D2DBB
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Capture::IGraphicsCapturePicker>{ 0x5A1711B3,0xAD79,0x4B4A,{ 0x93,0x36,0x13,0x18,0xFD,0xDE,0x35,0x39 } }; // 5A1711B3-AD79-4B4A-9336-1318FDDE3539
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Capture::IGraphicsCaptureSession>{ 0x814E42A9,0xF70F,0x4AD7,{ 0x93,0x9B,0xFD,0xDC,0xC6,0xEB,0x88,0x0D } }; // 814E42A9-F70F-4AD7-939B-FDDCC6EB880D
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Capture::IGraphicsCaptureSession2>{ 0x2C39AE40,0x7D2E,0x5044,{ 0x80,0x4E,0x8B,0x67,0x99,0xD4,0xCF,0x9E } }; // 2C39AE40-7D2E-5044-804E-8B6799D4CF9E
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Capture::IGraphicsCaptureSession3>{ 0xF2CDD966,0x22AE,0x5EA1,{ 0x95,0x96,0x3A,0x28,0x93,0x44,0xC3,0xBE } }; // F2CDD966-22AE-5EA1-9596-3A289344C3BE
    template <> inline constexpr guid guid_v<winrt::Windows::Graphics::Capture::IGraphicsCaptureSessionStatics>{ 0x2224A540,0x5974,0x49AA,{ 0xB2,0x32,0x08,0x82,0x53,0x6F,0x4C,0xB5 } }; // 2224A540-5974-49AA-B232-0882536F4CB5
    template <> struct default_interface<winrt::Windows::Graphics::Capture::Direct3D11CaptureFrame>{ using type = winrt::Windows::Graphics::Capture::IDirect3D11CaptureFrame; };
    template <> struct default_interface<winrt::Windows::Graphics::Capture::Direct3D11CaptureFramePool>{ using type = winrt::Windows::Graphics::Capture::IDirect3D11CaptureFramePool; };
    template <> struct default_interface<winrt::Windows::Graphics::Capture::GraphicsCaptureItem>{ using type = winrt::Windows::Graphics::Capture::IGraphicsCaptureItem; };
    template <> struct default_interface<winrt::Windows::Graphics::Capture::GraphicsCapturePicker>{ using type = winrt::Windows::Graphics::Capture::IGraphicsCapturePicker; };
    template <> struct default_interface<winrt::Windows::Graphics::Capture::GraphicsCaptureSession>{ using type = winrt::Windows::Graphics::Capture::IGraphicsCaptureSession; };
    template <> struct abi<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFrame>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Surface(void**) noexcept = 0;
            virtual int32_t __stdcall get_SystemRelativeTime(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_ContentSize(struct struct_Windows_Graphics_SizeInt32*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFramePool>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Recreate(void*, int32_t, int32_t, struct struct_Windows_Graphics_SizeInt32) noexcept = 0;
            virtual int32_t __stdcall TryGetNextFrame(void**) noexcept = 0;
            virtual int32_t __stdcall add_FrameArrived(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_FrameArrived(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall CreateCaptureSession(void*, void**) noexcept = 0;
            virtual int32_t __stdcall get_DispatcherQueue(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(void*, int32_t, int32_t, struct struct_Windows_Graphics_SizeInt32, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateFreeThreaded(void*, int32_t, int32_t, struct struct_Windows_Graphics_SizeInt32, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Capture::IGraphicsCaptureAccessStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall RequestAccessAsync(int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Capture::IGraphicsCaptureItem>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DisplayName(void**) noexcept = 0;
            virtual int32_t __stdcall get_Size(struct struct_Windows_Graphics_SizeInt32*) noexcept = 0;
            virtual int32_t __stdcall add_Closed(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Closed(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Capture::IGraphicsCaptureItemStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateFromVisual(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Capture::IGraphicsCaptureItemStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall TryCreateFromWindowId(struct struct_Windows_UI_WindowId, void**) noexcept = 0;
            virtual int32_t __stdcall TryCreateFromDisplayId(struct struct_Windows_Graphics_DisplayId, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Capture::IGraphicsCapturePicker>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall PickSingleItemAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Capture::IGraphicsCaptureSession>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall StartCapture() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Capture::IGraphicsCaptureSession2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsCursorCaptureEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsCursorCaptureEnabled(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Capture::IGraphicsCaptureSession3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsBorderRequired(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsBorderRequired(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Graphics::Capture::IGraphicsCaptureSessionStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall IsSupported(bool*) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Graphics_Capture_IDirect3D11CaptureFrame
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface) Surface() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) SystemRelativeTime() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::SizeInt32) ContentSize() const;
    };
    template <> struct consume<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFrame>
    {
        template <typename D> using type = consume_Windows_Graphics_Capture_IDirect3D11CaptureFrame<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Capture_IDirect3D11CaptureFramePool
    {
        WINRT_IMPL_AUTO(void) Recreate(winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device, winrt::Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, int32_t numberOfBuffers, winrt::Windows::Graphics::SizeInt32 const& size) const;
        WINRT_IMPL_AUTO(winrt::Windows::Graphics::Capture::Direct3D11CaptureFrame) TryGetNextFrame() const;
        WINRT_IMPL_AUTO(winrt::event_token) FrameArrived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Capture::Direct3D11CaptureFramePool, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using FrameArrived_revoker = impl::event_revoker<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFramePool, &impl::abi_t<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFramePool>::remove_FrameArrived>;
        [[nodiscard]] FrameArrived_revoker FrameArrived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Capture::Direct3D11CaptureFramePool, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) FrameArrived(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::Windows::Graphics::Capture::GraphicsCaptureSession) CreateCaptureSession(winrt::Windows::Graphics::Capture::GraphicsCaptureItem const& item) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::System::DispatcherQueue) DispatcherQueue() const;
    };
    template <> struct consume<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFramePool>
    {
        template <typename D> using type = consume_Windows_Graphics_Capture_IDirect3D11CaptureFramePool<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Capture_IDirect3D11CaptureFramePoolStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Graphics::Capture::Direct3D11CaptureFramePool) Create(winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device, winrt::Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, int32_t numberOfBuffers, winrt::Windows::Graphics::SizeInt32 const& size) const;
    };
    template <> struct consume<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics>
    {
        template <typename D> using type = consume_Windows_Graphics_Capture_IDirect3D11CaptureFramePoolStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Capture_IDirect3D11CaptureFramePoolStatics2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Graphics::Capture::Direct3D11CaptureFramePool) CreateFreeThreaded(winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device, winrt::Windows::Graphics::DirectX::DirectXPixelFormat const& pixelFormat, int32_t numberOfBuffers, winrt::Windows::Graphics::SizeInt32 const& size) const;
    };
    template <> struct consume<winrt::Windows::Graphics::Capture::IDirect3D11CaptureFramePoolStatics2>
    {
        template <typename D> using type = consume_Windows_Graphics_Capture_IDirect3D11CaptureFramePoolStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Capture_IGraphicsCaptureAccessStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Security::Authorization::AppCapabilityAccess::AppCapabilityAccessStatus>) RequestAccessAsync(winrt::Windows::Graphics::Capture::GraphicsCaptureAccessKind const& request) const;
    };
    template <> struct consume<winrt::Windows::Graphics::Capture::IGraphicsCaptureAccessStatics>
    {
        template <typename D> using type = consume_Windows_Graphics_Capture_IGraphicsCaptureAccessStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Capture_IGraphicsCaptureItem
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DisplayName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Graphics::SizeInt32) Size() const;
        WINRT_IMPL_AUTO(winrt::event_token) Closed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Capture::GraphicsCaptureItem, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using Closed_revoker = impl::event_revoker<winrt::Windows::Graphics::Capture::IGraphicsCaptureItem, &impl::abi_t<winrt::Windows::Graphics::Capture::IGraphicsCaptureItem>::remove_Closed>;
        [[nodiscard]] Closed_revoker Closed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Capture::GraphicsCaptureItem, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) Closed(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Graphics::Capture::IGraphicsCaptureItem>
    {
        template <typename D> using type = consume_Windows_Graphics_Capture_IGraphicsCaptureItem<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Capture_IGraphicsCaptureItemStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Graphics::Capture::GraphicsCaptureItem) CreateFromVisual(winrt::Windows::UI::Composition::Visual const& visual) const;
    };
    template <> struct consume<winrt::Windows::Graphics::Capture::IGraphicsCaptureItemStatics>
    {
        template <typename D> using type = consume_Windows_Graphics_Capture_IGraphicsCaptureItemStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Capture_IGraphicsCaptureItemStatics2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Graphics::Capture::GraphicsCaptureItem) TryCreateFromWindowId(winrt::Windows::UI::WindowId const& windowId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Graphics::Capture::GraphicsCaptureItem) TryCreateFromDisplayId(winrt::Windows::Graphics::DisplayId const& displayId) const;
    };
    template <> struct consume<winrt::Windows::Graphics::Capture::IGraphicsCaptureItemStatics2>
    {
        template <typename D> using type = consume_Windows_Graphics_Capture_IGraphicsCaptureItemStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Capture_IGraphicsCapturePicker
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Graphics::Capture::GraphicsCaptureItem>) PickSingleItemAsync() const;
    };
    template <> struct consume<winrt::Windows::Graphics::Capture::IGraphicsCapturePicker>
    {
        template <typename D> using type = consume_Windows_Graphics_Capture_IGraphicsCapturePicker<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Capture_IGraphicsCaptureSession
    {
        WINRT_IMPL_AUTO(void) StartCapture() const;
    };
    template <> struct consume<winrt::Windows::Graphics::Capture::IGraphicsCaptureSession>
    {
        template <typename D> using type = consume_Windows_Graphics_Capture_IGraphicsCaptureSession<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Capture_IGraphicsCaptureSession2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsCursorCaptureEnabled() const;
        WINRT_IMPL_AUTO(void) IsCursorCaptureEnabled(bool value) const;
    };
    template <> struct consume<winrt::Windows::Graphics::Capture::IGraphicsCaptureSession2>
    {
        template <typename D> using type = consume_Windows_Graphics_Capture_IGraphicsCaptureSession2<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Capture_IGraphicsCaptureSession3
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsBorderRequired() const;
        WINRT_IMPL_AUTO(void) IsBorderRequired(bool value) const;
    };
    template <> struct consume<winrt::Windows::Graphics::Capture::IGraphicsCaptureSession3>
    {
        template <typename D> using type = consume_Windows_Graphics_Capture_IGraphicsCaptureSession3<D>;
    };
    template <typename D>
    struct consume_Windows_Graphics_Capture_IGraphicsCaptureSessionStatics
    {
        WINRT_IMPL_AUTO(bool) IsSupported() const;
    };
    template <> struct consume<winrt::Windows::Graphics::Capture::IGraphicsCaptureSessionStatics>
    {
        template <typename D> using type = consume_Windows_Graphics_Capture_IGraphicsCaptureSessionStatics<D>;
    };
}
#endif
