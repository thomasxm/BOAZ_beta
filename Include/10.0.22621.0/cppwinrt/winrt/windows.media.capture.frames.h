// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_Capture_Frames_H
#define WINRT_Windows_Media_Capture_Frames_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Media.Capture.h"
#include "winrt/impl/Windows.Devices.Enumeration.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.2.h"
#include "winrt/impl/Windows.Graphics.Imaging.2.h"
#include "winrt/impl/Windows.Media.2.h"
#include "winrt/impl/Windows.Media.Capture.2.h"
#include "winrt/impl/Windows.Media.Devices.2.h"
#include "winrt/impl/Windows.Media.Devices.Core.2.h"
#include "winrt/impl/Windows.Media.MediaProperties.2.h"
#include "winrt/impl/Windows.Perception.Spatial.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.WindowManagement.2.h"
#include "winrt/impl/Windows.Media.Capture.Frames.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::MediaFrameReference) consume_Windows_Media_Capture_Frames_IAudioMediaFrame<D>::FrameReference() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IAudioMediaFrame)->get_FrameReference(&value));
        return winrt::Windows::Media::Capture::Frames::MediaFrameReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::AudioEncodingProperties) consume_Windows_Media_Capture_Frames_IAudioMediaFrame<D>::AudioEncodingProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IAudioMediaFrame)->get_AudioEncodingProperties(&value));
        return winrt::Windows::Media::MediaProperties::AudioEncodingProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::AudioFrame) consume_Windows_Media_Capture_Frames_IAudioMediaFrame<D>::GetAudioFrame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IAudioMediaFrame)->GetAudioFrame(&value));
        return winrt::Windows::Media::AudioFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::MediaFrameReference) consume_Windows_Media_Capture_Frames_IBufferMediaFrame<D>::FrameReference() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IBufferMediaFrame)->get_FrameReference(&value));
        return winrt::Windows::Media::Capture::Frames::MediaFrameReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Media_Capture_Frames_IBufferMediaFrame<D>::Buffer() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IBufferMediaFrame)->get_Buffer(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::MediaFrameReference) consume_Windows_Media_Capture_Frames_IDepthMediaFrame<D>::FrameReference() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IDepthMediaFrame)->get_FrameReference(&value));
        return winrt::Windows::Media::Capture::Frames::MediaFrameReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::VideoMediaFrame) consume_Windows_Media_Capture_Frames_IDepthMediaFrame<D>::VideoMediaFrame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IDepthMediaFrame)->get_VideoMediaFrame(&value));
        return winrt::Windows::Media::Capture::Frames::VideoMediaFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::DepthMediaFrameFormat) consume_Windows_Media_Capture_Frames_IDepthMediaFrame<D>::DepthFormat() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IDepthMediaFrame)->get_DepthFormat(&value));
        return winrt::Windows::Media::Capture::Frames::DepthMediaFrameFormat{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Devices::Core::DepthCorrelatedCoordinateMapper) consume_Windows_Media_Capture_Frames_IDepthMediaFrame<D>::TryCreateCoordinateMapper(winrt::Windows::Media::Devices::Core::CameraIntrinsics const& cameraIntrinsics, winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const& coordinateSystem) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IDepthMediaFrame)->TryCreateCoordinateMapper(*(void**)(&cameraIntrinsics), *(void**)(&coordinateSystem), &value));
        return winrt::Windows::Media::Devices::Core::DepthCorrelatedCoordinateMapper{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_Frames_IDepthMediaFrame2<D>::MaxReliableDepth() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IDepthMediaFrame2)->get_MaxReliableDepth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_Frames_IDepthMediaFrame2<D>::MinReliableDepth() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IDepthMediaFrame2)->get_MinReliableDepth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::VideoMediaFrameFormat) consume_Windows_Media_Capture_Frames_IDepthMediaFrameFormat<D>::VideoFormat() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IDepthMediaFrameFormat)->get_VideoFormat(&value));
        return winrt::Windows::Media::Capture::Frames::VideoMediaFrameFormat{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Capture_Frames_IDepthMediaFrameFormat<D>::DepthScaleInMeters() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IDepthMediaFrameFormat)->get_DepthScaleInMeters(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::MediaFrameReference) consume_Windows_Media_Capture_Frames_IInfraredMediaFrame<D>::FrameReference() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IInfraredMediaFrame)->get_FrameReference(&value));
        return winrt::Windows::Media::Capture::Frames::MediaFrameReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::VideoMediaFrame) consume_Windows_Media_Capture_Frames_IInfraredMediaFrame<D>::VideoMediaFrame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IInfraredMediaFrame)->get_VideoMediaFrame(&value));
        return winrt::Windows::Media::Capture::Frames::VideoMediaFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_Frames_IInfraredMediaFrame<D>::IsIlluminated() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IInfraredMediaFrame)->get_IsIlluminated(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_Frames_IMediaFrameFormat<D>::MajorType() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameFormat)->get_MajorType(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_Frames_IMediaFrameFormat<D>::Subtype() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameFormat)->get_Subtype(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::MediaRatio) consume_Windows_Media_Capture_Frames_IMediaFrameFormat<D>::FrameRate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameFormat)->get_FrameRate(&value));
        return winrt::Windows::Media::MediaProperties::MediaRatio{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>) consume_Windows_Media_Capture_Frames_IMediaFrameFormat<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameFormat)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::VideoMediaFrameFormat) consume_Windows_Media_Capture_Frames_IMediaFrameFormat<D>::VideoFormat() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameFormat)->get_VideoFormat(&value));
        return winrt::Windows::Media::Capture::Frames::VideoMediaFrameFormat{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::AudioEncodingProperties) consume_Windows_Media_Capture_Frames_IMediaFrameFormat2<D>::AudioEncodingProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameFormat2)->get_AudioEncodingProperties(&value));
        return winrt::Windows::Media::MediaProperties::AudioEncodingProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_Frames_IMediaFrameReader<D>::FrameArrived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::Frames::MediaFrameReader, winrt::Windows::Media::Capture::Frames::MediaFrameArrivedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameReader)->add_FrameArrived(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_Frames_IMediaFrameReader<D>::FrameArrived_revoker consume_Windows_Media_Capture_Frames_IMediaFrameReader<D>::FrameArrived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::Frames::MediaFrameReader, winrt::Windows::Media::Capture::Frames::MediaFrameArrivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, FrameArrived_revoker>(this, FrameArrived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_Frames_IMediaFrameReader<D>::FrameArrived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameReader)->remove_FrameArrived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::MediaFrameReference) consume_Windows_Media_Capture_Frames_IMediaFrameReader<D>::TryAcquireLatestFrame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameReader)->TryAcquireLatestFrame(&value));
        return winrt::Windows::Media::Capture::Frames::MediaFrameReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MediaFrameReaderStartStatus>) consume_Windows_Media_Capture_Frames_IMediaFrameReader<D>::StartAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameReader)->StartAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MediaFrameReaderStartStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_Frames_IMediaFrameReader<D>::StopAsync() const
    {
        void* action{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameReader)->StopAsync(&action));
        return winrt::Windows::Foundation::IAsyncAction{ action, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_Frames_IMediaFrameReader2<D>::AcquisitionMode(winrt::Windows::Media::Capture::Frames::MediaFrameReaderAcquisitionMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameReader2)->put_AcquisitionMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::MediaFrameReaderAcquisitionMode) consume_Windows_Media_Capture_Frames_IMediaFrameReader2<D>::AcquisitionMode() const
    {
        winrt::Windows::Media::Capture::Frames::MediaFrameReaderAcquisitionMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameReader2)->get_AcquisitionMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::MediaFrameSourceKind) consume_Windows_Media_Capture_Frames_IMediaFrameReference<D>::SourceKind() const
    {
        winrt::Windows::Media::Capture::Frames::MediaFrameSourceKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameReference)->get_SourceKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::MediaFrameFormat) consume_Windows_Media_Capture_Frames_IMediaFrameReference<D>::Format() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameReference)->get_Format(&value));
        return winrt::Windows::Media::Capture::Frames::MediaFrameFormat{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Media_Capture_Frames_IMediaFrameReference<D>::SystemRelativeTime() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameReference)->get_SystemRelativeTime(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Capture_Frames_IMediaFrameReference<D>::Duration() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameReference)->get_Duration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>) consume_Windows_Media_Capture_Frames_IMediaFrameReference<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameReference)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::BufferMediaFrame) consume_Windows_Media_Capture_Frames_IMediaFrameReference<D>::BufferMediaFrame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameReference)->get_BufferMediaFrame(&value));
        return winrt::Windows::Media::Capture::Frames::BufferMediaFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::VideoMediaFrame) consume_Windows_Media_Capture_Frames_IMediaFrameReference<D>::VideoMediaFrame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameReference)->get_VideoMediaFrame(&value));
        return winrt::Windows::Media::Capture::Frames::VideoMediaFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem) consume_Windows_Media_Capture_Frames_IMediaFrameReference<D>::CoordinateSystem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameReference)->get_CoordinateSystem(&value));
        return winrt::Windows::Perception::Spatial::SpatialCoordinateSystem{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::AudioMediaFrame) consume_Windows_Media_Capture_Frames_IMediaFrameReference2<D>::AudioMediaFrame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameReference2)->get_AudioMediaFrame(&value));
        return winrt::Windows::Media::Capture::Frames::AudioMediaFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::MediaFrameSourceInfo) consume_Windows_Media_Capture_Frames_IMediaFrameSource<D>::Info() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSource)->get_Info(&value));
        return winrt::Windows::Media::Capture::Frames::MediaFrameSourceInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::MediaFrameSourceController) consume_Windows_Media_Capture_Frames_IMediaFrameSource<D>::Controller() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSource)->get_Controller(&value));
        return winrt::Windows::Media::Capture::Frames::MediaFrameSourceController{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::Frames::MediaFrameFormat>) consume_Windows_Media_Capture_Frames_IMediaFrameSource<D>::SupportedFormats() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSource)->get_SupportedFormats(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::Frames::MediaFrameFormat>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::MediaFrameFormat) consume_Windows_Media_Capture_Frames_IMediaFrameSource<D>::CurrentFormat() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSource)->get_CurrentFormat(&value));
        return winrt::Windows::Media::Capture::Frames::MediaFrameFormat{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_Frames_IMediaFrameSource<D>::SetFormatAsync(winrt::Windows::Media::Capture::Frames::MediaFrameFormat const& format) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSource)->SetFormatAsync(*(void**)(&format), &value));
        return winrt::Windows::Foundation::IAsyncAction{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_Frames_IMediaFrameSource<D>::FormatChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::Frames::MediaFrameSource, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSource)->add_FormatChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_Frames_IMediaFrameSource<D>::FormatChanged_revoker consume_Windows_Media_Capture_Frames_IMediaFrameSource<D>::FormatChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::Frames::MediaFrameSource, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, FormatChanged_revoker>(this, FormatChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_Frames_IMediaFrameSource<D>::FormatChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSource)->remove_FormatChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Devices::Core::CameraIntrinsics) consume_Windows_Media_Capture_Frames_IMediaFrameSource<D>::TryGetCameraIntrinsics(winrt::Windows::Media::Capture::Frames::MediaFrameFormat const& format) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSource)->TryGetCameraIntrinsics(*(void**)(&format), &value));
        return winrt::Windows::Media::Devices::Core::CameraIntrinsics{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MediaFrameSourceGetPropertyResult>) consume_Windows_Media_Capture_Frames_IMediaFrameSourceController<D>::GetPropertyAsync(param::hstring const& propertyId) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSourceController)->GetPropertyAsync(*(void**)(&propertyId), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MediaFrameSourceGetPropertyResult>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MediaFrameSourceSetPropertyStatus>) consume_Windows_Media_Capture_Frames_IMediaFrameSourceController<D>::SetPropertyAsync(param::hstring const& propertyId, winrt::Windows::Foundation::IInspectable const& propertyValue) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSourceController)->SetPropertyAsync(*(void**)(&propertyId), *(void**)(&propertyValue), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MediaFrameSourceSetPropertyStatus>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Devices::VideoDeviceController) consume_Windows_Media_Capture_Frames_IMediaFrameSourceController<D>::VideoDeviceController() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSourceController)->get_VideoDeviceController(&value));
        return winrt::Windows::Media::Devices::VideoDeviceController{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MediaFrameSourceGetPropertyResult>) consume_Windows_Media_Capture_Frames_IMediaFrameSourceController2<D>::GetPropertyByExtendedIdAsync(array_view<uint8_t const> extendedPropertyId, winrt::Windows::Foundation::IReference<uint32_t> const& maxPropertyValueSize) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSourceController2)->GetPropertyByExtendedIdAsync(extendedPropertyId.size(), get_abi(extendedPropertyId), *(void**)(&maxPropertyValueSize), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MediaFrameSourceGetPropertyResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MediaFrameSourceSetPropertyStatus>) consume_Windows_Media_Capture_Frames_IMediaFrameSourceController2<D>::SetPropertyByExtendedIdAsync(array_view<uint8_t const> extendedPropertyId, array_view<uint8_t const> propertyValue) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSourceController2)->SetPropertyByExtendedIdAsync(extendedPropertyId.size(), get_abi(extendedPropertyId), propertyValue.size(), get_abi(propertyValue), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MediaFrameSourceSetPropertyStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Devices::AudioDeviceController) consume_Windows_Media_Capture_Frames_IMediaFrameSourceController3<D>::AudioDeviceController() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSourceController3)->get_AudioDeviceController(&value));
        return winrt::Windows::Media::Devices::AudioDeviceController{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::MediaFrameSourceGetPropertyStatus) consume_Windows_Media_Capture_Frames_IMediaFrameSourceGetPropertyResult<D>::Status() const
    {
        winrt::Windows::Media::Capture::Frames::MediaFrameSourceGetPropertyStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSourceGetPropertyResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_Media_Capture_Frames_IMediaFrameSourceGetPropertyResult<D>::Value() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSourceGetPropertyResult)->get_Value(&value));
        return winrt::Windows::Foundation::IInspectable{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_Frames_IMediaFrameSourceGroup<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSourceGroup)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_Frames_IMediaFrameSourceGroup<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSourceGroup)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::Frames::MediaFrameSourceInfo>) consume_Windows_Media_Capture_Frames_IMediaFrameSourceGroup<D>::SourceInfos() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSourceGroup)->get_SourceInfos(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::Frames::MediaFrameSourceInfo>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::Frames::MediaFrameSourceGroup>>) consume_Windows_Media_Capture_Frames_IMediaFrameSourceGroupStatics<D>::FindAllAsync() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSourceGroupStatics)->FindAllAsync(&value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::Frames::MediaFrameSourceGroup>>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MediaFrameSourceGroup>) consume_Windows_Media_Capture_Frames_IMediaFrameSourceGroupStatics<D>::FromIdAsync(param::hstring const& id) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSourceGroupStatics)->FromIdAsync(*(void**)(&id), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MediaFrameSourceGroup>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_Frames_IMediaFrameSourceGroupStatics<D>::GetDeviceSelector() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSourceGroupStatics)->GetDeviceSelector(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_Frames_IMediaFrameSourceInfo<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::MediaStreamType) consume_Windows_Media_Capture_Frames_IMediaFrameSourceInfo<D>::MediaStreamType() const
    {
        winrt::Windows::Media::Capture::MediaStreamType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo)->get_MediaStreamType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::MediaFrameSourceKind) consume_Windows_Media_Capture_Frames_IMediaFrameSourceInfo<D>::SourceKind() const
    {
        winrt::Windows::Media::Capture::Frames::MediaFrameSourceKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo)->get_SourceKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::MediaFrameSourceGroup) consume_Windows_Media_Capture_Frames_IMediaFrameSourceInfo<D>::SourceGroup() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo)->get_SourceGroup(&value));
        return winrt::Windows::Media::Capture::Frames::MediaFrameSourceGroup{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceInformation) consume_Windows_Media_Capture_Frames_IMediaFrameSourceInfo<D>::DeviceInformation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo)->get_DeviceInformation(&value));
        return winrt::Windows::Devices::Enumeration::DeviceInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>) consume_Windows_Media_Capture_Frames_IMediaFrameSourceInfo<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Perception::Spatial::SpatialCoordinateSystem) consume_Windows_Media_Capture_Frames_IMediaFrameSourceInfo<D>::CoordinateSystem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo)->get_CoordinateSystem(&value));
        return winrt::Windows::Perception::Spatial::SpatialCoordinateSystem{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Capture_Frames_IMediaFrameSourceInfo2<D>::ProfileId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo2)->get_ProfileId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription>) consume_Windows_Media_Capture_Frames_IMediaFrameSourceInfo2<D>::VideoProfileMediaDescription() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo2)->get_VideoProfileMediaDescription(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::Panel) consume_Windows_Media_Capture_Frames_IMediaFrameSourceInfo3<D>::GetRelativePanel(winrt::Windows::UI::WindowManagement::DisplayRegion const& displayRegion) const
    {
        winrt::Windows::Devices::Enumeration::Panel result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo3)->GetRelativePanel(*(void**)(&displayRegion), reinterpret_cast<int32_t*>(&result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Capture_Frames_IMediaFrameSourceInfo4<D>::IsShareable() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo4)->get_IsShareable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Capture_Frames_IMultiSourceMediaFrameReader<D>::FrameArrived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::Frames::MultiSourceMediaFrameReader, winrt::Windows::Media::Capture::Frames::MultiSourceMediaFrameArrivedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader)->add_FrameArrived(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Capture_Frames_IMultiSourceMediaFrameReader<D>::FrameArrived_revoker consume_Windows_Media_Capture_Frames_IMultiSourceMediaFrameReader<D>::FrameArrived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::Frames::MultiSourceMediaFrameReader, winrt::Windows::Media::Capture::Frames::MultiSourceMediaFrameArrivedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, FrameArrived_revoker>(this, FrameArrived(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_Frames_IMultiSourceMediaFrameReader<D>::FrameArrived(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader)->remove_FrameArrived(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::MultiSourceMediaFrameReference) consume_Windows_Media_Capture_Frames_IMultiSourceMediaFrameReader<D>::TryAcquireLatestFrame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader)->TryAcquireLatestFrame(&value));
        return winrt::Windows::Media::Capture::Frames::MultiSourceMediaFrameReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MultiSourceMediaFrameReaderStartStatus>) consume_Windows_Media_Capture_Frames_IMultiSourceMediaFrameReader<D>::StartAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader)->StartAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MultiSourceMediaFrameReaderStartStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Capture_Frames_IMultiSourceMediaFrameReader<D>::StopAsync() const
    {
        void* action{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader)->StopAsync(&action));
        return winrt::Windows::Foundation::IAsyncAction{ action, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Capture_Frames_IMultiSourceMediaFrameReader2<D>::AcquisitionMode(winrt::Windows::Media::Capture::Frames::MediaFrameReaderAcquisitionMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader2)->put_AcquisitionMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::MediaFrameReaderAcquisitionMode) consume_Windows_Media_Capture_Frames_IMultiSourceMediaFrameReader2<D>::AcquisitionMode() const
    {
        winrt::Windows::Media::Capture::Frames::MediaFrameReaderAcquisitionMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader2)->get_AcquisitionMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::MediaFrameReference) consume_Windows_Media_Capture_Frames_IMultiSourceMediaFrameReference<D>::TryGetFrameReferenceBySourceId(param::hstring const& sourceId) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameReference)->TryGetFrameReferenceBySourceId(*(void**)(&sourceId), &value));
        return winrt::Windows::Media::Capture::Frames::MediaFrameReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::MediaFrameReference) consume_Windows_Media_Capture_Frames_IVideoMediaFrame<D>::FrameReference() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IVideoMediaFrame)->get_FrameReference(&value));
        return winrt::Windows::Media::Capture::Frames::MediaFrameReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::VideoMediaFrameFormat) consume_Windows_Media_Capture_Frames_IVideoMediaFrame<D>::VideoFormat() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IVideoMediaFrame)->get_VideoFormat(&value));
        return winrt::Windows::Media::Capture::Frames::VideoMediaFrameFormat{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Imaging::SoftwareBitmap) consume_Windows_Media_Capture_Frames_IVideoMediaFrame<D>::SoftwareBitmap() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IVideoMediaFrame)->get_SoftwareBitmap(&value));
        return winrt::Windows::Graphics::Imaging::SoftwareBitmap{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface) consume_Windows_Media_Capture_Frames_IVideoMediaFrame<D>::Direct3DSurface() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IVideoMediaFrame)->get_Direct3DSurface(&value));
        return winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Devices::Core::CameraIntrinsics) consume_Windows_Media_Capture_Frames_IVideoMediaFrame<D>::CameraIntrinsics() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IVideoMediaFrame)->get_CameraIntrinsics(&value));
        return winrt::Windows::Media::Devices::Core::CameraIntrinsics{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::InfraredMediaFrame) consume_Windows_Media_Capture_Frames_IVideoMediaFrame<D>::InfraredMediaFrame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IVideoMediaFrame)->get_InfraredMediaFrame(&value));
        return winrt::Windows::Media::Capture::Frames::InfraredMediaFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::DepthMediaFrame) consume_Windows_Media_Capture_Frames_IVideoMediaFrame<D>::DepthMediaFrame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IVideoMediaFrame)->get_DepthMediaFrame(&value));
        return winrt::Windows::Media::Capture::Frames::DepthMediaFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::VideoFrame) consume_Windows_Media_Capture_Frames_IVideoMediaFrame<D>::GetVideoFrame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IVideoMediaFrame)->GetVideoFrame(&value));
        return winrt::Windows::Media::VideoFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::MediaFrameFormat) consume_Windows_Media_Capture_Frames_IVideoMediaFrameFormat<D>::MediaFrameFormat() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IVideoMediaFrameFormat)->get_MediaFrameFormat(&value));
        return winrt::Windows::Media::Capture::Frames::MediaFrameFormat{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::Frames::DepthMediaFrameFormat) consume_Windows_Media_Capture_Frames_IVideoMediaFrameFormat<D>::DepthFormat() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IVideoMediaFrameFormat)->get_DepthFormat(&value));
        return winrt::Windows::Media::Capture::Frames::DepthMediaFrameFormat{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_Frames_IVideoMediaFrameFormat<D>::Width() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IVideoMediaFrameFormat)->get_Width(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Capture_Frames_IVideoMediaFrameFormat<D>::Height() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Capture::Frames::IVideoMediaFrameFormat)->get_Height(&value));
        return value;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IAudioMediaFrame> : produce_base<D, winrt::Windows::Media::Capture::Frames::IAudioMediaFrame>
    {
        int32_t __stdcall get_FrameReference(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::MediaFrameReference>(this->shim().FrameReference());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioEncodingProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().AudioEncodingProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAudioFrame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::AudioFrame>(this->shim().GetAudioFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IBufferMediaFrame> : produce_base<D, winrt::Windows::Media::Capture::Frames::IBufferMediaFrame>
    {
        int32_t __stdcall get_FrameReference(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::MediaFrameReference>(this->shim().FrameReference());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Buffer(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().Buffer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IDepthMediaFrame> : produce_base<D, winrt::Windows::Media::Capture::Frames::IDepthMediaFrame>
    {
        int32_t __stdcall get_FrameReference(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::MediaFrameReference>(this->shim().FrameReference());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoMediaFrame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::VideoMediaFrame>(this->shim().VideoMediaFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DepthFormat(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::DepthMediaFrameFormat>(this->shim().DepthFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryCreateCoordinateMapper(void* cameraIntrinsics, void* coordinateSystem, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Devices::Core::DepthCorrelatedCoordinateMapper>(this->shim().TryCreateCoordinateMapper(*reinterpret_cast<winrt::Windows::Media::Devices::Core::CameraIntrinsics const*>(&cameraIntrinsics), *reinterpret_cast<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem const*>(&coordinateSystem)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IDepthMediaFrame2> : produce_base<D, winrt::Windows::Media::Capture::Frames::IDepthMediaFrame2>
    {
        int32_t __stdcall get_MaxReliableDepth(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MaxReliableDepth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinReliableDepth(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().MinReliableDepth());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IDepthMediaFrameFormat> : produce_base<D, winrt::Windows::Media::Capture::Frames::IDepthMediaFrameFormat>
    {
        int32_t __stdcall get_VideoFormat(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::VideoMediaFrameFormat>(this->shim().VideoFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DepthScaleInMeters(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().DepthScaleInMeters());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IInfraredMediaFrame> : produce_base<D, winrt::Windows::Media::Capture::Frames::IInfraredMediaFrame>
    {
        int32_t __stdcall get_FrameReference(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::MediaFrameReference>(this->shim().FrameReference());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoMediaFrame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::VideoMediaFrame>(this->shim().VideoMediaFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsIlluminated(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsIlluminated());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IMediaFrameArrivedEventArgs> : produce_base<D, winrt::Windows::Media::Capture::Frames::IMediaFrameArrivedEventArgs>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IMediaFrameFormat> : produce_base<D, winrt::Windows::Media::Capture::Frames::IMediaFrameFormat>
    {
        int32_t __stdcall get_MajorType(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().MajorType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Subtype(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Subtype());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FrameRate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::MediaRatio>(this->shim().FrameRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormat(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::VideoMediaFrameFormat>(this->shim().VideoFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IMediaFrameFormat2> : produce_base<D, winrt::Windows::Media::Capture::Frames::IMediaFrameFormat2>
    {
        int32_t __stdcall get_AudioEncodingProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().AudioEncodingProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IMediaFrameReader> : produce_base<D, winrt::Windows::Media::Capture::Frames::IMediaFrameReader>
    {
        int32_t __stdcall add_FrameArrived(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().FrameArrived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::Frames::MediaFrameReader, winrt::Windows::Media::Capture::Frames::MediaFrameArrivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_FrameArrived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FrameArrived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall TryAcquireLatestFrame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::MediaFrameReference>(this->shim().TryAcquireLatestFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MediaFrameReaderStartStatus>>(this->shim().StartAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopAsync(void** action) noexcept final try
        {
            clear_abi(action);
            typename D::abi_guard guard(this->shim());
            *action = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().StopAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IMediaFrameReader2> : produce_base<D, winrt::Windows::Media::Capture::Frames::IMediaFrameReader2>
    {
        int32_t __stdcall put_AcquisitionMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AcquisitionMode(*reinterpret_cast<winrt::Windows::Media::Capture::Frames::MediaFrameReaderAcquisitionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AcquisitionMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::MediaFrameReaderAcquisitionMode>(this->shim().AcquisitionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IMediaFrameReference> : produce_base<D, winrt::Windows::Media::Capture::Frames::IMediaFrameReference>
    {
        int32_t __stdcall get_SourceKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::MediaFrameSourceKind>(this->shim().SourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Format(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::MediaFrameFormat>(this->shim().Format());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SystemRelativeTime(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().SystemRelativeTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Duration(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BufferMediaFrame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::BufferMediaFrame>(this->shim().BufferMediaFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoMediaFrame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::VideoMediaFrame>(this->shim().VideoMediaFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CoordinateSystem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem>(this->shim().CoordinateSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IMediaFrameReference2> : produce_base<D, winrt::Windows::Media::Capture::Frames::IMediaFrameReference2>
    {
        int32_t __stdcall get_AudioMediaFrame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::AudioMediaFrame>(this->shim().AudioMediaFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IMediaFrameSource> : produce_base<D, winrt::Windows::Media::Capture::Frames::IMediaFrameSource>
    {
        int32_t __stdcall get_Info(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::MediaFrameSourceInfo>(this->shim().Info());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Controller(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::MediaFrameSourceController>(this->shim().Controller());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedFormats(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::Frames::MediaFrameFormat>>(this->shim().SupportedFormats());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CurrentFormat(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::MediaFrameFormat>(this->shim().CurrentFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetFormatAsync(void* format, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().SetFormatAsync(*reinterpret_cast<winrt::Windows::Media::Capture::Frames::MediaFrameFormat const*>(&format)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_FormatChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().FormatChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::Frames::MediaFrameSource, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_FormatChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FormatChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall TryGetCameraIntrinsics(void* format, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Devices::Core::CameraIntrinsics>(this->shim().TryGetCameraIntrinsics(*reinterpret_cast<winrt::Windows::Media::Capture::Frames::MediaFrameFormat const*>(&format)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IMediaFrameSourceController> : produce_base<D, winrt::Windows::Media::Capture::Frames::IMediaFrameSourceController>
    {
        int32_t __stdcall GetPropertyAsync(void* propertyId, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MediaFrameSourceGetPropertyResult>>(this->shim().GetPropertyAsync(*reinterpret_cast<hstring const*>(&propertyId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPropertyAsync(void* propertyId, void* propertyValue, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MediaFrameSourceSetPropertyStatus>>(this->shim().SetPropertyAsync(*reinterpret_cast<hstring const*>(&propertyId), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&propertyValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoDeviceController(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Devices::VideoDeviceController>(this->shim().VideoDeviceController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IMediaFrameSourceController2> : produce_base<D, winrt::Windows::Media::Capture::Frames::IMediaFrameSourceController2>
    {
        int32_t __stdcall GetPropertyByExtendedIdAsync(uint32_t __extendedPropertyIdSize, uint8_t* extendedPropertyId, void* maxPropertyValueSize, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MediaFrameSourceGetPropertyResult>>(this->shim().GetPropertyByExtendedIdAsync(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(extendedPropertyId), reinterpret_cast<uint8_t const *>(extendedPropertyId) + __extendedPropertyIdSize), *reinterpret_cast<winrt::Windows::Foundation::IReference<uint32_t> const*>(&maxPropertyValueSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPropertyByExtendedIdAsync(uint32_t __extendedPropertyIdSize, uint8_t* extendedPropertyId, uint32_t __propertyValueSize, uint8_t* propertyValue, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MediaFrameSourceSetPropertyStatus>>(this->shim().SetPropertyByExtendedIdAsync(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(extendedPropertyId), reinterpret_cast<uint8_t const *>(extendedPropertyId) + __extendedPropertyIdSize), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(propertyValue), reinterpret_cast<uint8_t const *>(propertyValue) + __propertyValueSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IMediaFrameSourceController3> : produce_base<D, winrt::Windows::Media::Capture::Frames::IMediaFrameSourceController3>
    {
        int32_t __stdcall get_AudioDeviceController(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Devices::AudioDeviceController>(this->shim().AudioDeviceController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IMediaFrameSourceGetPropertyResult> : produce_base<D, winrt::Windows::Media::Capture::Frames::IMediaFrameSourceGetPropertyResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::MediaFrameSourceGetPropertyStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Value(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IMediaFrameSourceGroup> : produce_base<D, winrt::Windows::Media::Capture::Frames::IMediaFrameSourceGroup>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SourceInfos(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::Frames::MediaFrameSourceInfo>>(this->shim().SourceInfos());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IMediaFrameSourceGroupStatics> : produce_base<D, winrt::Windows::Media::Capture::Frames::IMediaFrameSourceGroupStatics>
    {
        int32_t __stdcall FindAllAsync(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::Frames::MediaFrameSourceGroup>>>(this->shim().FindAllAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromIdAsync(void* id, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MediaFrameSourceGroup>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelector(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo> : produce_base<D, winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MediaStreamType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::MediaStreamType>(this->shim().MediaStreamType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SourceKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::MediaFrameSourceKind>(this->shim().SourceKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SourceGroup(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::MediaFrameSourceGroup>(this->shim().SourceGroup());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeviceInformation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DeviceInformation>(this->shim().DeviceInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IMapView<winrt::guid, winrt::Windows::Foundation::IInspectable>>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CoordinateSystem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Perception::Spatial::SpatialCoordinateSystem>(this->shim().CoordinateSystem());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo2> : produce_base<D, winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo2>
    {
        int32_t __stdcall get_ProfileId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ProfileId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoProfileMediaDescription(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::MediaCaptureVideoProfileMediaDescription>>(this->shim().VideoProfileMediaDescription());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo3> : produce_base<D, winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo3>
    {
        int32_t __stdcall GetRelativePanel(void* displayRegion, int32_t* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Devices::Enumeration::Panel>(this->shim().GetRelativePanel(*reinterpret_cast<winrt::Windows::UI::WindowManagement::DisplayRegion const*>(&displayRegion)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo4> : produce_base<D, winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo4>
    {
        int32_t __stdcall get_IsShareable(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsShareable());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameArrivedEventArgs> : produce_base<D, winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameArrivedEventArgs>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader> : produce_base<D, winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader>
    {
        int32_t __stdcall add_FrameArrived(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().FrameArrived(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Capture::Frames::MultiSourceMediaFrameReader, winrt::Windows::Media::Capture::Frames::MultiSourceMediaFrameArrivedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_FrameArrived(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FrameArrived(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall TryAcquireLatestFrame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::MultiSourceMediaFrameReference>(this->shim().TryAcquireLatestFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Capture::Frames::MultiSourceMediaFrameReaderStartStatus>>(this->shim().StartAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopAsync(void** action) noexcept final try
        {
            clear_abi(action);
            typename D::abi_guard guard(this->shim());
            *action = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().StopAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader2> : produce_base<D, winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader2>
    {
        int32_t __stdcall put_AcquisitionMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AcquisitionMode(*reinterpret_cast<winrt::Windows::Media::Capture::Frames::MediaFrameReaderAcquisitionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AcquisitionMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::MediaFrameReaderAcquisitionMode>(this->shim().AcquisitionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameReference> : produce_base<D, winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameReference>
    {
        int32_t __stdcall TryGetFrameReferenceBySourceId(void* sourceId, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::MediaFrameReference>(this->shim().TryGetFrameReferenceBySourceId(*reinterpret_cast<hstring const*>(&sourceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IVideoMediaFrame> : produce_base<D, winrt::Windows::Media::Capture::Frames::IVideoMediaFrame>
    {
        int32_t __stdcall get_FrameReference(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::MediaFrameReference>(this->shim().FrameReference());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormat(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::VideoMediaFrameFormat>(this->shim().VideoFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SoftwareBitmap(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Imaging::SoftwareBitmap>(this->shim().SoftwareBitmap());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Direct3DSurface(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface>(this->shim().Direct3DSurface());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CameraIntrinsics(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Devices::Core::CameraIntrinsics>(this->shim().CameraIntrinsics());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InfraredMediaFrame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::InfraredMediaFrame>(this->shim().InfraredMediaFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DepthMediaFrame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::DepthMediaFrame>(this->shim().DepthMediaFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetVideoFrame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::VideoFrame>(this->shim().GetVideoFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Capture::Frames::IVideoMediaFrameFormat> : produce_base<D, winrt::Windows::Media::Capture::Frames::IVideoMediaFrameFormat>
    {
        int32_t __stdcall get_MediaFrameFormat(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::MediaFrameFormat>(this->shim().MediaFrameFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DepthFormat(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::Frames::DepthMediaFrameFormat>(this->shim().DepthFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Width(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Width());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Height(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Height());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Media::Capture::Frames
{
    inline auto MediaFrameSourceGroup::FindAllAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Capture::Frames::MediaFrameSourceGroup>>(*)(IMediaFrameSourceGroupStatics const&), MediaFrameSourceGroup, IMediaFrameSourceGroupStatics>([](IMediaFrameSourceGroupStatics const& f) { return f.FindAllAsync(); });
    }
    inline auto MediaFrameSourceGroup::FromIdAsync(param::hstring const& id)
    {
        return impl::call_factory<MediaFrameSourceGroup, IMediaFrameSourceGroupStatics>([&](IMediaFrameSourceGroupStatics const& f) { return f.FromIdAsync(id); });
    }
    inline auto MediaFrameSourceGroup::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IMediaFrameSourceGroupStatics const&), MediaFrameSourceGroup, IMediaFrameSourceGroupStatics>([](IMediaFrameSourceGroupStatics const& f) { return f.GetDeviceSelector(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IAudioMediaFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IBufferMediaFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IDepthMediaFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IDepthMediaFrame2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IDepthMediaFrameFormat> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IInfraredMediaFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameArrivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameFormat> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameFormat2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameReader2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameReference> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameReference2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameSourceController> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameSourceController2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameSourceController3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameSourceGetPropertyResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameSourceGroup> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameSourceGroupStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IMediaFrameSourceInfo4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameArrivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameReader2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IMultiSourceMediaFrameReference> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IVideoMediaFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::IVideoMediaFrameFormat> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::AudioMediaFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::BufferMediaFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::DepthMediaFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::DepthMediaFrameFormat> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::InfraredMediaFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::MediaFrameArrivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::MediaFrameFormat> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::MediaFrameReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::MediaFrameReference> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::MediaFrameSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::MediaFrameSourceController> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::MediaFrameSourceGetPropertyResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::MediaFrameSourceGroup> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::MediaFrameSourceInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::MultiSourceMediaFrameArrivedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::MultiSourceMediaFrameReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::MultiSourceMediaFrameReference> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::VideoMediaFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Capture::Frames::VideoMediaFrameFormat> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
