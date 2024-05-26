// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Xaml_Media_Imaging_H
#define WINRT_Windows_UI_Xaml_Media_Imaging_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.Xaml.Media.h"
#include "winrt/impl/Windows.ApplicationModel.Background.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Graphics.Imaging.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Xaml.Media.2.h"
#include "winrt/impl/Windows.UI.Xaml.Media.Imaging.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Imaging::BitmapCreateOptions) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::CreateOptions() const
    {
        winrt::Windows::UI::Xaml::Media::Imaging::BitmapCreateOptions value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage)->get_CreateOptions(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::CreateOptions(winrt::Windows::UI::Xaml::Media::Imaging::BitmapCreateOptions const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage)->put_CreateOptions(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::UriSource() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage)->get_UriSource(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::UriSource(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage)->put_UriSource(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::DecodePixelWidth() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage)->get_DecodePixelWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::DecodePixelWidth(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage)->put_DecodePixelWidth(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::DecodePixelHeight() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage)->get_DecodePixelHeight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::DecodePixelHeight(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage)->put_DecodePixelHeight(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::DownloadProgress(winrt::Windows::UI::Xaml::Media::Imaging::DownloadProgressEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage)->add_DownloadProgress(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::DownloadProgress_revoker consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::DownloadProgress(auto_revoke_t, winrt::Windows::UI::Xaml::Media::Imaging::DownloadProgressEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, DownloadProgress_revoker>(this, DownloadProgress(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::DownloadProgress(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage)->remove_DownloadProgress(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::ImageOpened(winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage)->add_ImageOpened(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::ImageOpened_revoker consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::ImageOpened(auto_revoke_t, winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, ImageOpened_revoker>(this, ImageOpened(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::ImageOpened(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage)->remove_ImageOpened(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::ImageFailed(winrt::Windows::UI::Xaml::ExceptionRoutedEventHandler const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage)->add_ImageFailed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::ImageFailed_revoker consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::ImageFailed(auto_revoke_t, winrt::Windows::UI::Xaml::ExceptionRoutedEventHandler const& handler) const
    {
        return impl::make_event_revoker<D, ImageFailed_revoker>(this, ImageFailed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage<D>::ImageFailed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage)->remove_ImageFailed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Imaging::DecodePixelType) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage2<D>::DecodePixelType() const
    {
        winrt::Windows::UI::Xaml::Media::Imaging::DecodePixelType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage2)->get_DecodePixelType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage2<D>::DecodePixelType(winrt::Windows::UI::Xaml::Media::Imaging::DecodePixelType const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage2)->put_DecodePixelType(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage3<D>::IsAnimatedBitmap() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage3)->get_IsAnimatedBitmap(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage3<D>::IsPlaying() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage3)->get_IsPlaying(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage3<D>::AutoPlay() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage3)->get_AutoPlay(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage3<D>::AutoPlay(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage3)->put_AutoPlay(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage3<D>::Play() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage3)->Play());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImage3<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage3)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Imaging::BitmapImage) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImageFactory<D>::CreateInstanceWithUriSource(winrt::Windows::Foundation::Uri const& uriSource) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImageFactory)->CreateInstanceWithUriSource(*(void**)(&uriSource), &value));
        return winrt::Windows::UI::Xaml::Media::Imaging::BitmapImage{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImageStatics<D>::CreateOptionsProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics)->get_CreateOptionsProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImageStatics<D>::UriSourceProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics)->get_UriSourceProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImageStatics<D>::DecodePixelWidthProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics)->get_DecodePixelWidthProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImageStatics<D>::DecodePixelHeightProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics)->get_DecodePixelHeightProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImageStatics2<D>::DecodePixelTypeProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics2)->get_DecodePixelTypeProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImageStatics3<D>::IsAnimatedBitmapProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics3)->get_IsAnimatedBitmapProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImageStatics3<D>::IsPlayingProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics3)->get_IsPlayingProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Imaging_IBitmapImageStatics3<D>::AutoPlayProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics3)->get_AutoPlayProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Media_Imaging_IBitmapSource<D>::PixelWidth() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapSource)->get_PixelWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Media_Imaging_IBitmapSource<D>::PixelHeight() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapSource)->get_PixelHeight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Imaging_IBitmapSource<D>::SetSource(winrt::Windows::Storage::Streams::IRandomAccessStream const& streamSource) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapSource)->SetSource(*(void**)(&streamSource)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_UI_Xaml_Media_Imaging_IBitmapSource<D>::SetSourceAsync(winrt::Windows::Storage::Streams::IRandomAccessStream const& streamSource) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapSource)->SetSourceAsync(*(void**)(&streamSource), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Imaging::BitmapSource) consume_Windows_UI_Xaml_Media_Imaging_IBitmapSourceFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapSourceFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Media::Imaging::BitmapSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Imaging_IBitmapSourceStatics<D>::PixelWidthProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapSourceStatics)->get_PixelWidthProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Imaging_IBitmapSourceStatics<D>::PixelHeightProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IBitmapSourceStatics)->get_PixelHeightProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Media_Imaging_IDownloadProgressEventArgs<D>::Progress() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IDownloadProgressEventArgs)->get_Progress(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Imaging_IDownloadProgressEventArgs<D>::Progress(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IDownloadProgressEventArgs)->put_Progress(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Media_Imaging_IRenderTargetBitmap<D>::PixelWidth() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmap)->get_PixelWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Xaml_Media_Imaging_IRenderTargetBitmap<D>::PixelHeight() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmap)->get_PixelHeight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_UI_Xaml_Media_Imaging_IRenderTargetBitmap<D>::RenderAsync(winrt::Windows::UI::Xaml::UIElement const& element) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmap)->RenderAsync(*(void**)(&element), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_UI_Xaml_Media_Imaging_IRenderTargetBitmap<D>::RenderAsync(winrt::Windows::UI::Xaml::UIElement const& element, int32_t scaledWidth, int32_t scaledHeight) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmap)->RenderToSizeAsync(*(void**)(&element), scaledWidth, scaledHeight, &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>) consume_Windows_UI_Xaml_Media_Imaging_IRenderTargetBitmap<D>::GetPixelsAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmap)->GetPixelsAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Imaging_IRenderTargetBitmapStatics<D>::PixelWidthProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmapStatics)->get_PixelWidthProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Imaging_IRenderTargetBitmapStatics<D>::PixelHeightProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmapStatics)->get_PixelHeightProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_UI_Xaml_Media_Imaging_ISoftwareBitmapSource<D>::SetBitmapAsync(winrt::Windows::Graphics::Imaging::SoftwareBitmap const& softwareBitmap) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::ISoftwareBitmapSource)->SetBitmapAsync(*(void**)(&softwareBitmap), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Imaging::SurfaceImageSource) consume_Windows_UI_Xaml_Media_Imaging_ISurfaceImageSourceFactory<D>::CreateInstanceWithDimensions(int32_t pixelWidth, int32_t pixelHeight, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::ISurfaceImageSourceFactory)->CreateInstanceWithDimensions(pixelWidth, pixelHeight, *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Media::Imaging::SurfaceImageSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Imaging::SurfaceImageSource) consume_Windows_UI_Xaml_Media_Imaging_ISurfaceImageSourceFactory<D>::CreateInstanceWithDimensionsAndOpacity(int32_t pixelWidth, int32_t pixelHeight, bool isOpaque, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::ISurfaceImageSourceFactory)->CreateInstanceWithDimensionsAndOpacity(pixelWidth, pixelHeight, isOpaque, *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Media::Imaging::SurfaceImageSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::UriSource() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSource)->get_UriSource(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::UriSource(winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSource)->put_UriSource(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::RasterizePixelWidth() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSource)->get_RasterizePixelWidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::RasterizePixelWidth(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSource)->put_RasterizePixelWidth(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::RasterizePixelHeight() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSource)->get_RasterizePixelHeight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::RasterizePixelHeight(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSource)->put_RasterizePixelHeight(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::Opened(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSource, winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSourceOpenedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSource)->add_Opened(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::Opened_revoker consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::Opened(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSource, winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSourceOpenedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Opened_revoker>(this, Opened(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::Opened(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSource)->remove_Opened(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::OpenFailed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSource, winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSourceFailedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSource)->add_OpenFailed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::OpenFailed_revoker consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::OpenFailed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSource, winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSourceFailedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, OpenFailed_revoker>(this, OpenFailed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::OpenFailed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSource)->remove_OpenFailed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSourceLoadStatus>) consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSource<D>::SetSourceAsync(winrt::Windows::Storage::Streams::IRandomAccessStream const& streamSource) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSource)->SetSourceAsync(*(void**)(&streamSource), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSourceLoadStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSource) consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSourceFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSourceFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSource) consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSourceFactory<D>::CreateInstanceWithUriSource(winrt::Windows::Foundation::Uri const& uriSource, winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSourceFactory)->CreateInstanceWithUriSource(*(void**)(&uriSource), *(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSourceLoadStatus) consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSourceFailedEventArgs<D>::Status() const
    {
        winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSourceLoadStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSourceFailedEventArgs)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSourceStatics<D>::UriSourceProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSourceStatics)->get_UriSourceProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSourceStatics<D>::RasterizePixelWidthProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSourceStatics)->get_RasterizePixelWidthProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Media_Imaging_ISvgImageSourceStatics<D>::RasterizePixelHeightProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSourceStatics)->get_RasterizePixelHeightProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Imaging::VirtualSurfaceImageSource) consume_Windows_UI_Xaml_Media_Imaging_IVirtualSurfaceImageSourceFactory<D>::CreateInstanceWithDimensions(int32_t pixelWidth, int32_t pixelHeight) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IVirtualSurfaceImageSourceFactory)->CreateInstanceWithDimensions(pixelWidth, pixelHeight, &value));
        return winrt::Windows::UI::Xaml::Media::Imaging::VirtualSurfaceImageSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Imaging::VirtualSurfaceImageSource) consume_Windows_UI_Xaml_Media_Imaging_IVirtualSurfaceImageSourceFactory<D>::CreateInstanceWithDimensionsAndOpacity(int32_t pixelWidth, int32_t pixelHeight, bool isOpaque) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IVirtualSurfaceImageSourceFactory)->CreateInstanceWithDimensionsAndOpacity(pixelWidth, pixelHeight, isOpaque, &value));
        return winrt::Windows::UI::Xaml::Media::Imaging::VirtualSurfaceImageSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_UI_Xaml_Media_Imaging_IWriteableBitmap<D>::PixelBuffer() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IWriteableBitmap)->get_PixelBuffer(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Imaging_IWriteableBitmap<D>::Invalidate() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IWriteableBitmap)->Invalidate());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Imaging::WriteableBitmap) consume_Windows_UI_Xaml_Media_Imaging_IWriteableBitmapFactory<D>::CreateInstanceWithDimensions(int32_t pixelWidth, int32_t pixelHeight) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IWriteableBitmapFactory)->CreateInstanceWithDimensions(pixelWidth, pixelHeight, &value));
        return winrt::Windows::UI::Xaml::Media::Imaging::WriteableBitmap{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Imaging::XamlRenderingBackgroundTask) consume_Windows_UI_Xaml_Media_Imaging_IXamlRenderingBackgroundTaskFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTaskFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Media::Imaging::XamlRenderingBackgroundTask{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Media_Imaging_IXamlRenderingBackgroundTaskOverrides<D>::OnRun(winrt::Windows::ApplicationModel::Background::IBackgroundTaskInstance const& taskInstance) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTaskOverrides)->OnRun(*(void**)(&taskInstance)));
    }
    template <typename H> struct delegate<winrt::Windows::UI::Xaml::Media::Imaging::DownloadProgressEventHandler, H> final : implements_delegate<winrt::Windows::UI::Xaml::Media::Imaging::DownloadProgressEventHandler, H>
    {
        delegate(H&& handler) : implements_delegate<winrt::Windows::UI::Xaml::Media::Imaging::DownloadProgressEventHandler, H>(std::forward<H>(handler)) {}

        int32_t __stdcall Invoke(void* sender, void* e) noexcept final try
        {
            (*this)(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&sender), *reinterpret_cast<winrt::Windows::UI::Xaml::Media::Imaging::DownloadProgressEventArgs const*>(&e));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage> : produce_base<D, winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage>
    {
        int32_t __stdcall get_CreateOptions(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Imaging::BitmapCreateOptions>(this->shim().CreateOptions());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CreateOptions(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CreateOptions(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Imaging::BitmapCreateOptions const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UriSource(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().UriSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_UriSource(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UriSource(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DecodePixelWidth(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().DecodePixelWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DecodePixelWidth(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DecodePixelWidth(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DecodePixelHeight(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().DecodePixelHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DecodePixelHeight(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DecodePixelHeight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_DownloadProgress(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().DownloadProgress(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Imaging::DownloadProgressEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_DownloadProgress(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DownloadProgress(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ImageOpened(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ImageOpened(*reinterpret_cast<winrt::Windows::UI::Xaml::RoutedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ImageOpened(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ImageOpened(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ImageFailed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ImageFailed(*reinterpret_cast<winrt::Windows::UI::Xaml::ExceptionRoutedEventHandler const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ImageFailed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ImageFailed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage2> : produce_base<D, winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage2>
    {
        int32_t __stdcall get_DecodePixelType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Imaging::DecodePixelType>(this->shim().DecodePixelType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DecodePixelType(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DecodePixelType(*reinterpret_cast<winrt::Windows::UI::Xaml::Media::Imaging::DecodePixelType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage3> : produce_base<D, winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage3>
    {
        int32_t __stdcall get_IsAnimatedBitmap(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAnimatedBitmap());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPlaying(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPlaying());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AutoPlay(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().AutoPlay());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AutoPlay(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AutoPlay(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Play() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Play();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Stop() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Stop();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImageFactory> : produce_base<D, winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImageFactory>
    {
        int32_t __stdcall CreateInstanceWithUriSource(void* uriSource, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Imaging::BitmapImage>(this->shim().CreateInstanceWithUriSource(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uriSource)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics>
    {
        int32_t __stdcall get_CreateOptionsProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().CreateOptionsProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UriSourceProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().UriSourceProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DecodePixelWidthProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().DecodePixelWidthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DecodePixelHeightProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().DecodePixelHeightProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics2> : produce_base<D, winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics2>
    {
        int32_t __stdcall get_DecodePixelTypeProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().DecodePixelTypeProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics3> : produce_base<D, winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics3>
    {
        int32_t __stdcall get_IsAnimatedBitmapProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsAnimatedBitmapProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPlayingProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().IsPlayingProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AutoPlayProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().AutoPlayProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Imaging::IBitmapSource> : produce_base<D, winrt::Windows::UI::Xaml::Media::Imaging::IBitmapSource>
    {
        int32_t __stdcall get_PixelWidth(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().PixelWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PixelHeight(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().PixelHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetSource(void* streamSource) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetSource(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStream const*>(&streamSource));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetSourceAsync(void* streamSource, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SetSourceAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStream const*>(&streamSource)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Imaging::IBitmapSourceFactory> : produce_base<D, winrt::Windows::UI::Xaml::Media::Imaging::IBitmapSourceFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Imaging::BitmapSource>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Imaging::IBitmapSourceStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Imaging::IBitmapSourceStatics>
    {
        int32_t __stdcall get_PixelWidthProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().PixelWidthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PixelHeightProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().PixelHeightProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Imaging::IDownloadProgressEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Media::Imaging::IDownloadProgressEventArgs>
    {
        int32_t __stdcall get_Progress(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Progress());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Progress(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Progress(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmap> : produce_base<D, winrt::Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmap>
    {
        int32_t __stdcall get_PixelWidth(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().PixelWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PixelHeight(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().PixelHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RenderAsync(void* element, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().RenderAsync(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RenderToSizeAsync(void* element, int32_t scaledWidth, int32_t scaledHeight, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().RenderAsync(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&element), scaledWidth, scaledHeight));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPixelsAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>>(this->shim().GetPixelsAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmapStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmapStatics>
    {
        int32_t __stdcall get_PixelWidthProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().PixelWidthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PixelHeightProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().PixelHeightProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Imaging::ISoftwareBitmapSource> : produce_base<D, winrt::Windows::UI::Xaml::Media::Imaging::ISoftwareBitmapSource>
    {
        int32_t __stdcall SetBitmapAsync(void* softwareBitmap, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SetBitmapAsync(*reinterpret_cast<winrt::Windows::Graphics::Imaging::SoftwareBitmap const*>(&softwareBitmap)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Imaging::ISurfaceImageSource> : produce_base<D, winrt::Windows::UI::Xaml::Media::Imaging::ISurfaceImageSource>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Imaging::ISurfaceImageSourceFactory> : produce_base<D, winrt::Windows::UI::Xaml::Media::Imaging::ISurfaceImageSourceFactory>
    {
        int32_t __stdcall CreateInstanceWithDimensions(int32_t pixelWidth, int32_t pixelHeight, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Imaging::SurfaceImageSource>(this->shim().CreateInstanceWithDimensions(pixelWidth, pixelHeight, *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateInstanceWithDimensionsAndOpacity(int32_t pixelWidth, int32_t pixelHeight, bool isOpaque, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Imaging::SurfaceImageSource>(this->shim().CreateInstanceWithDimensionsAndOpacity(pixelWidth, pixelHeight, isOpaque, *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSource> : produce_base<D, winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSource>
    {
        int32_t __stdcall get_UriSource(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().UriSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_UriSource(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UriSource(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RasterizePixelWidth(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().RasterizePixelWidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RasterizePixelWidth(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RasterizePixelWidth(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RasterizePixelHeight(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().RasterizePixelHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RasterizePixelHeight(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RasterizePixelHeight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_Opened(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Opened(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSource, winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSourceOpenedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Opened(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Opened(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_OpenFailed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().OpenFailed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSource, winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSourceFailedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_OpenFailed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OpenFailed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall SetSourceAsync(void* streamSource, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSourceLoadStatus>>(this->shim().SetSourceAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStream const*>(&streamSource)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSourceFactory> : produce_base<D, winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSourceFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSource>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateInstanceWithUriSource(void* uriSource, void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSource>(this->shim().CreateInstanceWithUriSource(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uriSource), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSourceFailedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSourceFailedEventArgs>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSourceLoadStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSourceOpenedEventArgs> : produce_base<D, winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSourceOpenedEventArgs>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSourceStatics> : produce_base<D, winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSourceStatics>
    {
        int32_t __stdcall get_UriSourceProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().UriSourceProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RasterizePixelWidthProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().RasterizePixelWidthProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RasterizePixelHeightProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().RasterizePixelHeightProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Imaging::IVirtualSurfaceImageSource> : produce_base<D, winrt::Windows::UI::Xaml::Media::Imaging::IVirtualSurfaceImageSource>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Imaging::IVirtualSurfaceImageSourceFactory> : produce_base<D, winrt::Windows::UI::Xaml::Media::Imaging::IVirtualSurfaceImageSourceFactory>
    {
        int32_t __stdcall CreateInstanceWithDimensions(int32_t pixelWidth, int32_t pixelHeight, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Imaging::VirtualSurfaceImageSource>(this->shim().CreateInstanceWithDimensions(pixelWidth, pixelHeight));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateInstanceWithDimensionsAndOpacity(int32_t pixelWidth, int32_t pixelHeight, bool isOpaque, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Imaging::VirtualSurfaceImageSource>(this->shim().CreateInstanceWithDimensionsAndOpacity(pixelWidth, pixelHeight, isOpaque));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Imaging::IWriteableBitmap> : produce_base<D, winrt::Windows::UI::Xaml::Media::Imaging::IWriteableBitmap>
    {
        int32_t __stdcall get_PixelBuffer(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().PixelBuffer());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Invalidate() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Invalidate();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Imaging::IWriteableBitmapFactory> : produce_base<D, winrt::Windows::UI::Xaml::Media::Imaging::IWriteableBitmapFactory>
    {
        int32_t __stdcall CreateInstanceWithDimensions(int32_t pixelWidth, int32_t pixelHeight, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Imaging::WriteableBitmap>(this->shim().CreateInstanceWithDimensions(pixelWidth, pixelHeight));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTask> : produce_base<D, winrt::Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTask>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTaskFactory> : produce_base<D, winrt::Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTaskFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Media::Imaging::XamlRenderingBackgroundTask>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTaskOverrides> : produce_base<D, winrt::Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTaskOverrides>
    {
        int32_t __stdcall OnRun(void* taskInstance) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OnRun(*reinterpret_cast<winrt::Windows::ApplicationModel::Background::IBackgroundTaskInstance const*>(&taskInstance));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
template <typename T, typename D>
struct __declspec(empty_bases) produce_dispatch_to_overridable<T, D, winrt::Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTaskOverrides>
    : produce_dispatch_to_overridable_base<T, D, winrt::Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTaskOverrides>
{
    auto OnRun(winrt::Windows::ApplicationModel::Background::IBackgroundTaskInstance const& taskInstance)
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.OnRun(taskInstance);
        }

        return this->shim().OnRun(taskInstance);
    }
};
}
WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Media::Imaging
{
    constexpr auto operator|(BitmapCreateOptions const left, BitmapCreateOptions const right) noexcept
    {
        return static_cast<BitmapCreateOptions>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(BitmapCreateOptions& left, BitmapCreateOptions const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(BitmapCreateOptions const left, BitmapCreateOptions const right) noexcept
    {
        return static_cast<BitmapCreateOptions>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(BitmapCreateOptions& left, BitmapCreateOptions const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(BitmapCreateOptions const value) noexcept
    {
        return static_cast<BitmapCreateOptions>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(BitmapCreateOptions const left, BitmapCreateOptions const right) noexcept
    {
        return static_cast<BitmapCreateOptions>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(BitmapCreateOptions& left, BitmapCreateOptions const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline BitmapImage::BitmapImage() :
        BitmapImage(impl::call_factory_cast<BitmapImage(*)(winrt::Windows::Foundation::IActivationFactory const&), BitmapImage>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<BitmapImage>(); }))
    {
    }
    inline BitmapImage::BitmapImage(winrt::Windows::Foundation::Uri const& uriSource) :
        BitmapImage(impl::call_factory<BitmapImage, IBitmapImageFactory>([&](IBitmapImageFactory const& f) { return f.CreateInstanceWithUriSource(uriSource); }))
    {
    }
    inline auto BitmapImage::CreateOptionsProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IBitmapImageStatics const&), BitmapImage, IBitmapImageStatics>([](IBitmapImageStatics const& f) { return f.CreateOptionsProperty(); });
    }
    inline auto BitmapImage::UriSourceProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IBitmapImageStatics const&), BitmapImage, IBitmapImageStatics>([](IBitmapImageStatics const& f) { return f.UriSourceProperty(); });
    }
    inline auto BitmapImage::DecodePixelWidthProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IBitmapImageStatics const&), BitmapImage, IBitmapImageStatics>([](IBitmapImageStatics const& f) { return f.DecodePixelWidthProperty(); });
    }
    inline auto BitmapImage::DecodePixelHeightProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IBitmapImageStatics const&), BitmapImage, IBitmapImageStatics>([](IBitmapImageStatics const& f) { return f.DecodePixelHeightProperty(); });
    }
    inline auto BitmapImage::DecodePixelTypeProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IBitmapImageStatics2 const&), BitmapImage, IBitmapImageStatics2>([](IBitmapImageStatics2 const& f) { return f.DecodePixelTypeProperty(); });
    }
    inline auto BitmapImage::IsAnimatedBitmapProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IBitmapImageStatics3 const&), BitmapImage, IBitmapImageStatics3>([](IBitmapImageStatics3 const& f) { return f.IsAnimatedBitmapProperty(); });
    }
    inline auto BitmapImage::IsPlayingProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IBitmapImageStatics3 const&), BitmapImage, IBitmapImageStatics3>([](IBitmapImageStatics3 const& f) { return f.IsPlayingProperty(); });
    }
    inline auto BitmapImage::AutoPlayProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IBitmapImageStatics3 const&), BitmapImage, IBitmapImageStatics3>([](IBitmapImageStatics3 const& f) { return f.AutoPlayProperty(); });
    }
    inline auto BitmapSource::PixelWidthProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IBitmapSourceStatics const&), BitmapSource, IBitmapSourceStatics>([](IBitmapSourceStatics const& f) { return f.PixelWidthProperty(); });
    }
    inline auto BitmapSource::PixelHeightProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IBitmapSourceStatics const&), BitmapSource, IBitmapSourceStatics>([](IBitmapSourceStatics const& f) { return f.PixelHeightProperty(); });
    }
    inline RenderTargetBitmap::RenderTargetBitmap() :
        RenderTargetBitmap(impl::call_factory_cast<RenderTargetBitmap(*)(winrt::Windows::Foundation::IActivationFactory const&), RenderTargetBitmap>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<RenderTargetBitmap>(); }))
    {
    }
    inline auto RenderTargetBitmap::PixelWidthProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IRenderTargetBitmapStatics const&), RenderTargetBitmap, IRenderTargetBitmapStatics>([](IRenderTargetBitmapStatics const& f) { return f.PixelWidthProperty(); });
    }
    inline auto RenderTargetBitmap::PixelHeightProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IRenderTargetBitmapStatics const&), RenderTargetBitmap, IRenderTargetBitmapStatics>([](IRenderTargetBitmapStatics const& f) { return f.PixelHeightProperty(); });
    }
    inline SoftwareBitmapSource::SoftwareBitmapSource() :
        SoftwareBitmapSource(impl::call_factory_cast<SoftwareBitmapSource(*)(winrt::Windows::Foundation::IActivationFactory const&), SoftwareBitmapSource>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SoftwareBitmapSource>(); }))
    {
    }
    inline SurfaceImageSource::SurfaceImageSource(int32_t pixelWidth, int32_t pixelHeight)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<SurfaceImageSource, ISurfaceImageSourceFactory>([&](ISurfaceImageSourceFactory const& f) { return f.CreateInstanceWithDimensions(pixelWidth, pixelHeight, baseInterface, innerInterface); });
    }
    inline SurfaceImageSource::SurfaceImageSource(int32_t pixelWidth, int32_t pixelHeight, bool isOpaque)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<SurfaceImageSource, ISurfaceImageSourceFactory>([&](ISurfaceImageSourceFactory const& f) { return f.CreateInstanceWithDimensionsAndOpacity(pixelWidth, pixelHeight, isOpaque, baseInterface, innerInterface); });
    }
    inline SvgImageSource::SvgImageSource()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<SvgImageSource, ISvgImageSourceFactory>([&](ISvgImageSourceFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline SvgImageSource::SvgImageSource(winrt::Windows::Foundation::Uri const& uriSource)
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<SvgImageSource, ISvgImageSourceFactory>([&](ISvgImageSourceFactory const& f) { return f.CreateInstanceWithUriSource(uriSource, baseInterface, innerInterface); });
    }
    inline auto SvgImageSource::UriSourceProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISvgImageSourceStatics const&), SvgImageSource, ISvgImageSourceStatics>([](ISvgImageSourceStatics const& f) { return f.UriSourceProperty(); });
    }
    inline auto SvgImageSource::RasterizePixelWidthProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISvgImageSourceStatics const&), SvgImageSource, ISvgImageSourceStatics>([](ISvgImageSourceStatics const& f) { return f.RasterizePixelWidthProperty(); });
    }
    inline auto SvgImageSource::RasterizePixelHeightProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(ISvgImageSourceStatics const&), SvgImageSource, ISvgImageSourceStatics>([](ISvgImageSourceStatics const& f) { return f.RasterizePixelHeightProperty(); });
    }
    inline VirtualSurfaceImageSource::VirtualSurfaceImageSource(int32_t pixelWidth, int32_t pixelHeight) :
        VirtualSurfaceImageSource(impl::call_factory<VirtualSurfaceImageSource, IVirtualSurfaceImageSourceFactory>([&](IVirtualSurfaceImageSourceFactory const& f) { return f.CreateInstanceWithDimensions(pixelWidth, pixelHeight); }))
    {
    }
    inline VirtualSurfaceImageSource::VirtualSurfaceImageSource(int32_t pixelWidth, int32_t pixelHeight, bool isOpaque) :
        VirtualSurfaceImageSource(impl::call_factory<VirtualSurfaceImageSource, IVirtualSurfaceImageSourceFactory>([&](IVirtualSurfaceImageSourceFactory const& f) { return f.CreateInstanceWithDimensionsAndOpacity(pixelWidth, pixelHeight, isOpaque); }))
    {
    }
    inline WriteableBitmap::WriteableBitmap(int32_t pixelWidth, int32_t pixelHeight) :
        WriteableBitmap(impl::call_factory<WriteableBitmap, IWriteableBitmapFactory>([&](IWriteableBitmapFactory const& f) { return f.CreateInstanceWithDimensions(pixelWidth, pixelHeight); }))
    {
    }
    template <typename L> DownloadProgressEventHandler::DownloadProgressEventHandler(L handler) :
        DownloadProgressEventHandler(impl::make_delegate<DownloadProgressEventHandler>(std::forward<L>(handler)))
    {
    }
    template <typename F> DownloadProgressEventHandler::DownloadProgressEventHandler(F* handler) :
        DownloadProgressEventHandler([=](auto&&... args) { return handler(args...); })
    {
    }
    template <typename O, typename M> DownloadProgressEventHandler::DownloadProgressEventHandler(O* object, M method) :
        DownloadProgressEventHandler([=](auto&&... args) { return ((*object).*(method))(args...); })
    {
    }
    template <typename O, typename M> DownloadProgressEventHandler::DownloadProgressEventHandler(com_ptr<O>&& object, M method) :
        DownloadProgressEventHandler([o = std::move(object), method](auto&&... args) { return ((*o).*(method))(args...); })
    {
    }
    template <typename O, typename M> DownloadProgressEventHandler::DownloadProgressEventHandler(weak_ref<O>&& object, M method) :
        DownloadProgressEventHandler([o = std::move(object), method](auto&&... args) { if (auto s = o.get()) { ((*s).*(method))(args...); } })
    {
    }
    inline auto DownloadProgressEventHandler::operator()(winrt::Windows::Foundation::IInspectable const& sender, winrt::Windows::UI::Xaml::Media::Imaging::DownloadProgressEventArgs const& e) const
    {
        check_hresult((*(impl::abi_t<DownloadProgressEventHandler>**)this)->Invoke(*(void**)(&sender), *(void**)(&e)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) IXamlRenderingBackgroundTaskOverridesT<D>::OnRun(winrt::Windows::ApplicationModel::Background::IBackgroundTaskInstance const& taskInstance) const
    {
        return shim().template try_as<IXamlRenderingBackgroundTaskOverrides>().OnRun(taskInstance);
    }
    template <typename D, typename... Interfaces>
    struct BitmapSourceT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Media::Imaging::IBitmapSource, winrt::Windows::UI::Xaml::Media::IImageSource, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, BitmapSource, winrt::Windows::UI::Xaml::Media::ImageSource, winrt::Windows::UI::Xaml::DependencyObject>
    {
        using composable = BitmapSource;
    protected:
        BitmapSourceT()
        {
            impl::call_factory<BitmapSource, IBitmapSourceFactory>([&](IBitmapSourceFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct SurfaceImageSourceT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Media::Imaging::ISurfaceImageSource, winrt::Windows::UI::Xaml::Media::IImageSource, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, SurfaceImageSource, winrt::Windows::UI::Xaml::Media::ImageSource, winrt::Windows::UI::Xaml::DependencyObject>
    {
        using composable = SurfaceImageSource;
    protected:
        SurfaceImageSourceT(int32_t pixelWidth, int32_t pixelHeight)
        {
            impl::call_factory<SurfaceImageSource, ISurfaceImageSourceFactory>([&](ISurfaceImageSourceFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithDimensions(pixelWidth, pixelHeight, *this, this->m_inner); });
        }
        SurfaceImageSourceT(int32_t pixelWidth, int32_t pixelHeight, bool isOpaque)
        {
            impl::call_factory<SurfaceImageSource, ISurfaceImageSourceFactory>([&](ISurfaceImageSourceFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithDimensionsAndOpacity(pixelWidth, pixelHeight, isOpaque, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct SvgImageSourceT :
        implements<D, winrt::Windows::Foundation::IInspectable, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSource, winrt::Windows::UI::Xaml::Media::IImageSource, winrt::Windows::UI::Xaml::IDependencyObject, winrt::Windows::UI::Xaml::IDependencyObject2>,
        impl::base<D, SvgImageSource, winrt::Windows::UI::Xaml::Media::ImageSource, winrt::Windows::UI::Xaml::DependencyObject>
    {
        using composable = SvgImageSource;
    protected:
        SvgImageSourceT()
        {
            impl::call_factory<SvgImageSource, ISvgImageSourceFactory>([&](ISvgImageSourceFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
        SvgImageSourceT(winrt::Windows::Foundation::Uri const& uriSource)
        {
            impl::call_factory<SvgImageSource, ISvgImageSourceFactory>([&](ISvgImageSourceFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstanceWithUriSource(uriSource, *this, this->m_inner); });
        }
    };
    template <typename D, typename... Interfaces>
    struct XamlRenderingBackgroundTaskT :
        implements<D, winrt::Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTaskOverrides, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTask>,
        impl::base<D, XamlRenderingBackgroundTask>,
        winrt::Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTaskOverridesT<D>
    {
        using composable = XamlRenderingBackgroundTask;
    protected:
        XamlRenderingBackgroundTaskT()
        {
            impl::call_factory<XamlRenderingBackgroundTask, IXamlRenderingBackgroundTaskFactory>([&](IXamlRenderingBackgroundTaskFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImage3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImageFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapImageStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapSourceFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IBitmapSourceStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IDownloadProgressEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmap> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IRenderTargetBitmapStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::ISoftwareBitmapSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::ISurfaceImageSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::ISurfaceImageSourceFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSourceFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSourceFailedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSourceOpenedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::ISvgImageSourceStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IVirtualSurfaceImageSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IVirtualSurfaceImageSourceFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IWriteableBitmap> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IWriteableBitmapFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTask> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTaskFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::IXamlRenderingBackgroundTaskOverrides> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::BitmapImage> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::BitmapSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::DownloadProgressEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::RenderTargetBitmap> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::SoftwareBitmapSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::SurfaceImageSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSourceFailedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::SvgImageSourceOpenedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::VirtualSurfaceImageSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::WriteableBitmap> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Media::Imaging::XamlRenderingBackgroundTask> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
