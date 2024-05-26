// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_Core_H
#define WINRT_Windows_Media_Core_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Media.h"
#include "winrt/impl/Windows.ApplicationModel.AppService.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.2.h"
#include "winrt/impl/Windows.Graphics.Imaging.2.h"
#include "winrt/impl/Windows.Media.2.h"
#include "winrt/impl/Windows.Media.Capture.2.h"
#include "winrt/impl/Windows.Media.Capture.Frames.2.h"
#include "winrt/impl/Windows.Media.Devices.2.h"
#include "winrt/impl/Windows.Media.Devices.Core.2.h"
#include "winrt/impl/Windows.Media.Effects.2.h"
#include "winrt/impl/Windows.Media.FaceAnalysis.2.h"
#include "winrt/impl/Windows.Media.MediaProperties.2.h"
#include "winrt/impl/Windows.Media.Playback.2.h"
#include "winrt/impl/Windows.Media.Protection.2.h"
#include "winrt/impl/Windows.Media.Streaming.Adaptive.2.h"
#include "winrt/impl/Windows.Networking.BackgroundTransfer.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.FileProperties.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.Media.Core.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::AudioEncodingProperties) consume_Windows_Media_Core_IAudioStreamDescriptor<D>::EncodingProperties() const
    {
        void* encodingProperties{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IAudioStreamDescriptor)->get_EncodingProperties(&encodingProperties));
        return winrt::Windows::Media::MediaProperties::AudioEncodingProperties{ encodingProperties, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IAudioStreamDescriptor2<D>::LeadingEncoderPadding(winrt::Windows::Foundation::IReference<uint32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IAudioStreamDescriptor2)->put_LeadingEncoderPadding(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_Media_Core_IAudioStreamDescriptor2<D>::LeadingEncoderPadding() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IAudioStreamDescriptor2)->get_LeadingEncoderPadding(&value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IAudioStreamDescriptor2<D>::TrailingEncoderPadding(winrt::Windows::Foundation::IReference<uint32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IAudioStreamDescriptor2)->put_TrailingEncoderPadding(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) consume_Windows_Media_Core_IAudioStreamDescriptor2<D>::TrailingEncoderPadding() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IAudioStreamDescriptor2)->get_TrailingEncoderPadding(&value));
        return winrt::Windows::Foundation::IReference<uint32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::AudioStreamDescriptor) consume_Windows_Media_Core_IAudioStreamDescriptor3<D>::Copy() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IAudioStreamDescriptor3)->Copy(&result));
        return winrt::Windows::Media::Core::AudioStreamDescriptor{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::AudioStreamDescriptor) consume_Windows_Media_Core_IAudioStreamDescriptorFactory<D>::Create(winrt::Windows::Media::MediaProperties::AudioEncodingProperties const& encodingProperties) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IAudioStreamDescriptorFactory)->Create(*(void**)(&encodingProperties), &result));
        return winrt::Windows::Media::Core::AudioStreamDescriptor{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_IAudioTrack<D>::OpenFailed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::AudioTrack, winrt::Windows::Media::Core::AudioTrackOpenFailedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IAudioTrack)->add_OpenFailed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_IAudioTrack<D>::OpenFailed_revoker consume_Windows_Media_Core_IAudioTrack<D>::OpenFailed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::AudioTrack, winrt::Windows::Media::Core::AudioTrackOpenFailedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, OpenFailed_revoker>(this, OpenFailed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IAudioTrack<D>::OpenFailed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IAudioTrack)->remove_OpenFailed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::AudioEncodingProperties) consume_Windows_Media_Core_IAudioTrack<D>::GetEncodingProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IAudioTrack)->GetEncodingProperties(&value));
        return winrt::Windows::Media::MediaProperties::AudioEncodingProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackItem) consume_Windows_Media_Core_IAudioTrack<D>::PlaybackItem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IAudioTrack)->get_PlaybackItem(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackItem{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_IAudioTrack<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IAudioTrack)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::AudioTrackSupportInfo) consume_Windows_Media_Core_IAudioTrack<D>::SupportInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IAudioTrack)->get_SupportInfo(&value));
        return winrt::Windows::Media::Core::AudioTrackSupportInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Media_Core_IAudioTrackOpenFailedEventArgs<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IAudioTrackOpenFailedEventArgs)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaDecoderStatus) consume_Windows_Media_Core_IAudioTrackSupportInfo<D>::DecoderStatus() const
    {
        winrt::Windows::Media::Core::MediaDecoderStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IAudioTrackSupportInfo)->get_DecoderStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::AudioDecoderDegradation) consume_Windows_Media_Core_IAudioTrackSupportInfo<D>::Degradation() const
    {
        winrt::Windows::Media::Core::AudioDecoderDegradation value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IAudioTrackSupportInfo)->get_Degradation(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::AudioDecoderDegradationReason) consume_Windows_Media_Core_IAudioTrackSupportInfo<D>::DegradationReason() const
    {
        winrt::Windows::Media::Core::AudioDecoderDegradationReason value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IAudioTrackSupportInfo)->get_DegradationReason(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaSourceStatus) consume_Windows_Media_Core_IAudioTrackSupportInfo<D>::MediaSourceStatus() const
    {
        winrt::Windows::Media::Core::MediaSourceStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IAudioTrackSupportInfo)->get_MediaSourceStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IChapterCue<D>::Title(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IChapterCue)->put_Title(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_IChapterCue<D>::Title() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IChapterCue)->get_Title(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::CodecKind) consume_Windows_Media_Core_ICodecInfo<D>::Kind() const
    {
        winrt::Windows::Media::Core::CodecKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecInfo)->get_Kind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::CodecCategory) consume_Windows_Media_Core_ICodecInfo<D>::Category() const
    {
        winrt::Windows::Media::Core::CodecCategory value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecInfo)->get_Category(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_Media_Core_ICodecInfo<D>::Subtypes() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecInfo)->get_Subtypes(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecInfo<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecInfo)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Core_ICodecInfo<D>::IsTrusted() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecInfo)->get_IsTrusted(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Core::CodecInfo>>) consume_Windows_Media_Core_ICodecQuery<D>::FindAllAsync(winrt::Windows::Media::Core::CodecKind const& kind, winrt::Windows::Media::Core::CodecCategory const& category, param::hstring const& subType) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecQuery)->FindAllAsync(static_cast<int32_t>(kind), static_cast<int32_t>(category), *(void**)(&subType), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Core::CodecInfo>>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatDV25() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatDV25(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatDV50() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatDV50(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatDvc() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatDvc(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatDvh1() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatDvh1(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatDvhD() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatDvhD(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatDvsd() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatDvsd(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatDvsl() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatDvsl(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatH263() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatH263(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatH264() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatH264(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatH265() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatH265(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatH264ES() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatH264ES(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatHevc() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatHevc(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatHevcES() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatHevcES(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatM4S2() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatM4S2(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatMjpg() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatMjpg(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatMP43() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatMP43(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatMP4S() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatMP4S(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatMP4V() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatMP4V(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatMpeg2() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatMpeg2(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatVP80() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatVP80(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatVP90() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatVP90(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatMpg1() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatMpg1(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatMss1() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatMss1(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatMss2() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatMss2(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatWmv1() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatWmv1(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatWmv2() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatWmv2(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatWmv3() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatWmv3(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormatWvc1() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormatWvc1(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::VideoFormat420O() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_VideoFormat420O(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatAac() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatAac(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatAdts() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatAdts(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatAlac() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatAlac(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatAmrNB() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatAmrNB(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatAmrWB() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatAmrWB(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatAmrWP() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatAmrWP(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatDolbyAC3() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatDolbyAC3(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatDolbyAC3Spdif() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatDolbyAC3Spdif(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatDolbyDDPlus() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatDolbyDDPlus(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatDrm() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatDrm(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatDts() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatDts(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatFlac() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatFlac(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatFloat() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatFloat(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatMP3() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatMP3(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatMPeg() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatMPeg(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatMsp1() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatMsp1(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatOpus() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatOpus(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatPcm() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatPcm(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatWmaSpdif() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatWmaSpdif(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatWMAudioLossless() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatWMAudioLossless(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatWMAudioV8() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatWMAudioV8(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ICodecSubtypesStatics<D>::AudioFormatWMAudioV9() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ICodecSubtypesStatics)->get_AudioFormatWMAudioV9(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IDataCue<D>::Data(winrt::Windows::Storage::Streams::IBuffer const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IDataCue)->put_Data(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) consume_Windows_Media_Core_IDataCue<D>::Data() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IDataCue)->get_Data(&value));
        return winrt::Windows::Storage::Streams::IBuffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::PropertySet) consume_Windows_Media_Core_IDataCue2<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IDataCue2)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::PropertySet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::FaceDetectionEffectFrame) consume_Windows_Media_Core_IFaceDetectedEventArgs<D>::ResultFrame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IFaceDetectedEventArgs)->get_ResultFrame(&value));
        return winrt::Windows::Media::Core::FaceDetectionEffectFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IFaceDetectionEffect<D>::Enabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IFaceDetectionEffect)->put_Enabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Core_IFaceDetectionEffect<D>::Enabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IFaceDetectionEffect)->get_Enabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IFaceDetectionEffect<D>::DesiredDetectionInterval(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IFaceDetectionEffect)->put_DesiredDetectionInterval(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Core_IFaceDetectionEffect<D>::DesiredDetectionInterval() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IFaceDetectionEffect)->get_DesiredDetectionInterval(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_IFaceDetectionEffect<D>::FaceDetected(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::FaceDetectionEffect, winrt::Windows::Media::Core::FaceDetectedEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IFaceDetectionEffect)->add_FaceDetected(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Media_Core_IFaceDetectionEffect<D>::FaceDetected_revoker consume_Windows_Media_Core_IFaceDetectionEffect<D>::FaceDetected(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::FaceDetectionEffect, winrt::Windows::Media::Core::FaceDetectedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, FaceDetected_revoker>(this, FaceDetected(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IFaceDetectionEffect<D>::FaceDetected(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IFaceDetectionEffect)->remove_FaceDetected(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IFaceDetectionEffectDefinition<D>::DetectionMode(winrt::Windows::Media::Core::FaceDetectionMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IFaceDetectionEffectDefinition)->put_DetectionMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::FaceDetectionMode) consume_Windows_Media_Core_IFaceDetectionEffectDefinition<D>::DetectionMode() const
    {
        winrt::Windows::Media::Core::FaceDetectionMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IFaceDetectionEffectDefinition)->get_DetectionMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IFaceDetectionEffectDefinition<D>::SynchronousDetectionEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IFaceDetectionEffectDefinition)->put_SynchronousDetectionEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Core_IFaceDetectionEffectDefinition<D>::SynchronousDetectionEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IFaceDetectionEffectDefinition)->get_SynchronousDetectionEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::FaceAnalysis::DetectedFace>) consume_Windows_Media_Core_IFaceDetectionEffectFrame<D>::DetectedFaces() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IFaceDetectionEffectFrame)->get_DetectedFaces(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::FaceAnalysis::DetectedFace>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IHighDynamicRangeControl<D>::Enabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IHighDynamicRangeControl)->put_Enabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Core_IHighDynamicRangeControl<D>::Enabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IHighDynamicRangeControl)->get_Enabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Core_IHighDynamicRangeOutput<D>::Certainty() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IHighDynamicRangeOutput)->get_Certainty(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Devices::Core::FrameController>) consume_Windows_Media_Core_IHighDynamicRangeOutput<D>::FrameControllers() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IHighDynamicRangeOutput)->get_FrameControllers(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Devices::Core::FrameController>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextPoint) consume_Windows_Media_Core_IImageCue<D>::Position() const
    {
        winrt::Windows::Media::Core::TimedTextPoint value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IImageCue)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IImageCue<D>::Position(winrt::Windows::Media::Core::TimedTextPoint const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IImageCue)->put_Position(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextSize) consume_Windows_Media_Core_IImageCue<D>::Extent() const
    {
        winrt::Windows::Media::Core::TimedTextSize value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IImageCue)->get_Extent(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IImageCue<D>::Extent(winrt::Windows::Media::Core::TimedTextSize const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IImageCue)->put_Extent(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IImageCue<D>::SoftwareBitmap(winrt::Windows::Graphics::Imaging::SoftwareBitmap const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IImageCue)->put_SoftwareBitmap(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Imaging::SoftwareBitmap) consume_Windows_Media_Core_IImageCue<D>::SoftwareBitmap() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IImageCue)->get_SoftwareBitmap(&value));
        return winrt::Windows::Graphics::Imaging::SoftwareBitmap{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaStreamSource) consume_Windows_Media_Core_IInitializeMediaStreamSourceRequestedEventArgs<D>::Source() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IInitializeMediaStreamSourceRequestedEventArgs)->get_Source(&value));
        return winrt::Windows::Media::Core::MediaStreamSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStream) consume_Windows_Media_Core_IInitializeMediaStreamSourceRequestedEventArgs<D>::RandomAccessStream() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IInitializeMediaStreamSourceRequestedEventArgs)->get_RandomAccessStream(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStream{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Media_Core_IInitializeMediaStreamSourceRequestedEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IInitializeMediaStreamSourceRequestedEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Imaging::SoftwareBitmap) consume_Windows_Media_Core_ILowLightFusionResult<D>::Frame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ILowLightFusionResult)->get_Frame(&value));
        return winrt::Windows::Graphics::Imaging::SoftwareBitmap{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Graphics::Imaging::BitmapPixelFormat>) consume_Windows_Media_Core_ILowLightFusionStatics<D>::SupportedBitmapPixelFormats() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ILowLightFusionStatics)->get_SupportedBitmapPixelFormats(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Graphics::Imaging::BitmapPixelFormat>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_Core_ILowLightFusionStatics<D>::MaxSupportedFrameCount() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ILowLightFusionStatics)->get_MaxSupportedFrameCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Media::Core::LowLightFusionResult, double>) consume_Windows_Media_Core_ILowLightFusionStatics<D>::FuseAsync(param::async_iterable<winrt::Windows::Graphics::Imaging::SoftwareBitmap> const& frameSet) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ILowLightFusionStatics)->FuseAsync(*(void**)(&frameSet), &result));
        return winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Media::Core::LowLightFusionResult, double>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_IMediaBinder<D>::Binding(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaBinder, winrt::Windows::Media::Core::MediaBindingEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaBinder)->add_Binding(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_IMediaBinder<D>::Binding_revoker consume_Windows_Media_Core_IMediaBinder<D>::Binding(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaBinder, winrt::Windows::Media::Core::MediaBindingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Binding_revoker>(this, Binding(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaBinder<D>::Binding(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaBinder)->remove_Binding(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_IMediaBinder<D>::Token() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaBinder)->get_Token(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaBinder<D>::Token(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaBinder)->put_Token(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaSource) consume_Windows_Media_Core_IMediaBinder<D>::Source() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaBinder)->get_Source(&value));
        return winrt::Windows::Media::Core::MediaSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_IMediaBindingEventArgs<D>::Canceled(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaBindingEventArgs, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaBindingEventArgs)->add_Canceled(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_IMediaBindingEventArgs<D>::Canceled_revoker consume_Windows_Media_Core_IMediaBindingEventArgs<D>::Canceled(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaBindingEventArgs, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Canceled_revoker>(this, Canceled(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaBindingEventArgs<D>::Canceled(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaBindingEventArgs)->remove_Canceled(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaBinder) consume_Windows_Media_Core_IMediaBindingEventArgs<D>::MediaBinder() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaBindingEventArgs)->get_MediaBinder(&value));
        return winrt::Windows::Media::Core::MediaBinder{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Media_Core_IMediaBindingEventArgs<D>::GetDeferral() const
    {
        void* deferral{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaBindingEventArgs)->GetDeferral(&deferral));
        return winrt::Windows::Foundation::Deferral{ deferral, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaBindingEventArgs<D>::SetUri(winrt::Windows::Foundation::Uri const& uri) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaBindingEventArgs)->SetUri(*(void**)(&uri)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaBindingEventArgs<D>::SetStream(winrt::Windows::Storage::Streams::IRandomAccessStream const& stream, param::hstring const& contentType) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaBindingEventArgs)->SetStream(*(void**)(&stream), *(void**)(&contentType)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaBindingEventArgs<D>::SetStreamReference(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& stream, param::hstring const& contentType) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaBindingEventArgs)->SetStreamReference(*(void**)(&stream), *(void**)(&contentType)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaBindingEventArgs2<D>::SetAdaptiveMediaSource(winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSource const& mediaSource) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaBindingEventArgs2)->SetAdaptiveMediaSource(*(void**)(&mediaSource)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaBindingEventArgs2<D>::SetStorageFile(winrt::Windows::Storage::IStorageFile const& file) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaBindingEventArgs2)->SetStorageFile(*(void**)(&file)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaBindingEventArgs3<D>::SetDownloadOperation(winrt::Windows::Networking::BackgroundTransfer::DownloadOperation const& downloadOperation) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaBindingEventArgs3)->SetDownloadOperation(*(void**)(&downloadOperation)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaCue<D>::StartTime(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaCue)->put_StartTime(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Core_IMediaCue<D>::StartTime() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaCue)->get_StartTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaCue<D>::Duration(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaCue)->put_Duration(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Core_IMediaCue<D>::Duration() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaCue)->get_Duration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaCue<D>::Id(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaCue)->put_Id(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_IMediaCue<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaCue)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::IMediaCue) consume_Windows_Media_Core_IMediaCueEventArgs<D>::Cue() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaCueEventArgs)->get_Cue(&value));
        return winrt::Windows::Media::Core::IMediaCue{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_IMediaSource2<D>::OpenOperationCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaSource, winrt::Windows::Media::Core::MediaSourceOpenOperationCompletedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSource2)->add_OpenOperationCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_IMediaSource2<D>::OpenOperationCompleted_revoker consume_Windows_Media_Core_IMediaSource2<D>::OpenOperationCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaSource, winrt::Windows::Media::Core::MediaSourceOpenOperationCompletedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, OpenOperationCompleted_revoker>(this, OpenOperationCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaSource2<D>::OpenOperationCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSource2)->remove_OpenOperationCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::ValueSet) consume_Windows_Media_Core_IMediaSource2<D>::CustomProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSource2)->get_CustomProperties(&value));
        return winrt::Windows::Foundation::Collections::ValueSet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Media_Core_IMediaSource2<D>::Duration() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSource2)->get_Duration(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Core_IMediaSource2<D>::IsOpen() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSource2)->get_IsOpen(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::Media::Core::TimedTextSource>) consume_Windows_Media_Core_IMediaSource2<D>::ExternalTimedTextSources() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSource2)->get_ExternalTimedTextSources(&value));
        return winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::Media::Core::TimedTextSource>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::Media::Core::TimedMetadataTrack>) consume_Windows_Media_Core_IMediaSource2<D>::ExternalTimedMetadataTracks() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSource2)->get_ExternalTimedMetadataTracks(&value));
        return winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::Media::Core::TimedMetadataTrack>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_IMediaSource3<D>::StateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaSource, winrt::Windows::Media::Core::MediaSourceStateChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSource3)->add_StateChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_IMediaSource3<D>::StateChanged_revoker consume_Windows_Media_Core_IMediaSource3<D>::StateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaSource, winrt::Windows::Media::Core::MediaSourceStateChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, StateChanged_revoker>(this, StateChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaSource3<D>::StateChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSource3)->remove_StateChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaSourceState) consume_Windows_Media_Core_IMediaSource3<D>::State() const
    {
        winrt::Windows::Media::Core::MediaSourceState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSource3)->get_State(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaSource3<D>::Reset() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSource3)->Reset());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSource) consume_Windows_Media_Core_IMediaSource4<D>::AdaptiveMediaSource() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSource4)->get_AdaptiveMediaSource(&value));
        return winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaStreamSource) consume_Windows_Media_Core_IMediaSource4<D>::MediaStreamSource() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSource4)->get_MediaStreamSource(&value));
        return winrt::Windows::Media::Core::MediaStreamSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MseStreamSource) consume_Windows_Media_Core_IMediaSource4<D>::MseStreamSource() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSource4)->get_MseStreamSource(&value));
        return winrt::Windows::Media::Core::MseStreamSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) consume_Windows_Media_Core_IMediaSource4<D>::Uri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSource4)->get_Uri(&value));
        return winrt::Windows::Foundation::Uri{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Core_IMediaSource4<D>::OpenAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSource4)->OpenAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Networking::BackgroundTransfer::DownloadOperation) consume_Windows_Media_Core_IMediaSource5<D>::DownloadOperation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSource5)->get_DownloadOperation(&value));
        return winrt::Windows::Networking::BackgroundTransfer::DownloadOperation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_IMediaSourceAppServiceConnection<D>::InitializeMediaStreamSourceRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaSourceAppServiceConnection, winrt::Windows::Media::Core::InitializeMediaStreamSourceRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSourceAppServiceConnection)->add_InitializeMediaStreamSourceRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_IMediaSourceAppServiceConnection<D>::InitializeMediaStreamSourceRequested_revoker consume_Windows_Media_Core_IMediaSourceAppServiceConnection<D>::InitializeMediaStreamSourceRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaSourceAppServiceConnection, winrt::Windows::Media::Core::InitializeMediaStreamSourceRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, InitializeMediaStreamSourceRequested_revoker>(this, InitializeMediaStreamSourceRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaSourceAppServiceConnection<D>::InitializeMediaStreamSourceRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSourceAppServiceConnection)->remove_InitializeMediaStreamSourceRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaSourceAppServiceConnection<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSourceAppServiceConnection)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaSourceAppServiceConnection) consume_Windows_Media_Core_IMediaSourceAppServiceConnectionFactory<D>::Create(winrt::Windows::ApplicationModel::AppService::AppServiceConnection const& appServiceConnection) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSourceAppServiceConnectionFactory)->Create(*(void**)(&appServiceConnection), &result));
        return winrt::Windows::Media::Core::MediaSourceAppServiceConnection{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Media_Core_IMediaSourceError<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSourceError)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaSourceError) consume_Windows_Media_Core_IMediaSourceOpenOperationCompletedEventArgs<D>::Error() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSourceOpenOperationCompletedEventArgs)->get_Error(&value));
        return winrt::Windows::Media::Core::MediaSourceError{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaSourceState) consume_Windows_Media_Core_IMediaSourceStateChangedEventArgs<D>::OldState() const
    {
        winrt::Windows::Media::Core::MediaSourceState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSourceStateChangedEventArgs)->get_OldState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaSourceState) consume_Windows_Media_Core_IMediaSourceStateChangedEventArgs<D>::NewState() const
    {
        winrt::Windows::Media::Core::MediaSourceState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSourceStateChangedEventArgs)->get_NewState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaSource) consume_Windows_Media_Core_IMediaSourceStatics<D>::CreateFromAdaptiveMediaSource(winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSource const& mediaSource) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSourceStatics)->CreateFromAdaptiveMediaSource(*(void**)(&mediaSource), &result));
        return winrt::Windows::Media::Core::MediaSource{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaSource) consume_Windows_Media_Core_IMediaSourceStatics<D>::CreateFromMediaStreamSource(winrt::Windows::Media::Core::MediaStreamSource const& mediaSource) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSourceStatics)->CreateFromMediaStreamSource(*(void**)(&mediaSource), &result));
        return winrt::Windows::Media::Core::MediaSource{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaSource) consume_Windows_Media_Core_IMediaSourceStatics<D>::CreateFromMseStreamSource(winrt::Windows::Media::Core::MseStreamSource const& mediaSource) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSourceStatics)->CreateFromMseStreamSource(*(void**)(&mediaSource), &result));
        return winrt::Windows::Media::Core::MediaSource{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaSource) consume_Windows_Media_Core_IMediaSourceStatics<D>::CreateFromIMediaSource(winrt::Windows::Media::Core::IMediaSource const& mediaSource) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSourceStatics)->CreateFromIMediaSource(*(void**)(&mediaSource), &result));
        return winrt::Windows::Media::Core::MediaSource{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaSource) consume_Windows_Media_Core_IMediaSourceStatics<D>::CreateFromStorageFile(winrt::Windows::Storage::IStorageFile const& file) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSourceStatics)->CreateFromStorageFile(*(void**)(&file), &result));
        return winrt::Windows::Media::Core::MediaSource{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaSource) consume_Windows_Media_Core_IMediaSourceStatics<D>::CreateFromStream(winrt::Windows::Storage::Streams::IRandomAccessStream const& stream, param::hstring const& contentType) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSourceStatics)->CreateFromStream(*(void**)(&stream), *(void**)(&contentType), &result));
        return winrt::Windows::Media::Core::MediaSource{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaSource) consume_Windows_Media_Core_IMediaSourceStatics<D>::CreateFromStreamReference(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& stream, param::hstring const& contentType) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSourceStatics)->CreateFromStreamReference(*(void**)(&stream), *(void**)(&contentType), &result));
        return winrt::Windows::Media::Core::MediaSource{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaSource) consume_Windows_Media_Core_IMediaSourceStatics<D>::CreateFromUri(winrt::Windows::Foundation::Uri const& uri) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSourceStatics)->CreateFromUri(*(void**)(&uri), &result));
        return winrt::Windows::Media::Core::MediaSource{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaSource) consume_Windows_Media_Core_IMediaSourceStatics2<D>::CreateFromMediaBinder(winrt::Windows::Media::Core::MediaBinder const& binder) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSourceStatics2)->CreateFromMediaBinder(*(void**)(&binder), &result));
        return winrt::Windows::Media::Core::MediaSource{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaSource) consume_Windows_Media_Core_IMediaSourceStatics3<D>::CreateFromMediaFrameSource(winrt::Windows::Media::Capture::Frames::MediaFrameSource const& frameSource) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSourceStatics3)->CreateFromMediaFrameSource(*(void**)(&frameSource), &result));
        return winrt::Windows::Media::Core::MediaSource{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaSource) consume_Windows_Media_Core_IMediaSourceStatics4<D>::CreateFromDownloadOperation(winrt::Windows::Networking::BackgroundTransfer::DownloadOperation const& downloadOperation) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaSourceStatics4)->CreateFromDownloadOperation(*(void**)(&downloadOperation), &result));
        return winrt::Windows::Media::Core::MediaSource{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Core_IMediaStreamDescriptor<D>::IsSelected() const
    {
        bool selected{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamDescriptor)->get_IsSelected(&selected));
        return selected;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamDescriptor<D>::Name(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamDescriptor)->put_Name(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_IMediaStreamDescriptor<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamDescriptor)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamDescriptor<D>::Language(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamDescriptor)->put_Language(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_IMediaStreamDescriptor<D>::Language() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamDescriptor)->get_Language(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamDescriptor2<D>::Label(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamDescriptor2)->put_Label(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_IMediaStreamDescriptor2<D>::Label() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamDescriptor2)->get_Label(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_IMediaStreamSample<D>::Processed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaStreamSample, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSample)->add_Processed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_IMediaStreamSample<D>::Processed_revoker consume_Windows_Media_Core_IMediaStreamSample<D>::Processed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaStreamSample, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Processed_revoker>(this, Processed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSample<D>::Processed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSample)->remove_Processed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::Buffer) consume_Windows_Media_Core_IMediaStreamSample<D>::Buffer() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSample)->get_Buffer(&value));
        return winrt::Windows::Storage::Streams::Buffer{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Core_IMediaStreamSample<D>::Timestamp() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSample)->get_Timestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaStreamSamplePropertySet) consume_Windows_Media_Core_IMediaStreamSample<D>::ExtendedProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSample)->get_ExtendedProperties(&value));
        return winrt::Windows::Media::Core::MediaStreamSamplePropertySet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaStreamSampleProtectionProperties) consume_Windows_Media_Core_IMediaStreamSample<D>::Protection() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSample)->get_Protection(&value));
        return winrt::Windows::Media::Core::MediaStreamSampleProtectionProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSample<D>::DecodeTimestamp(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSample)->put_DecodeTimestamp(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Core_IMediaStreamSample<D>::DecodeTimestamp() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSample)->get_DecodeTimestamp(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSample<D>::Duration(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSample)->put_Duration(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Core_IMediaStreamSample<D>::Duration() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSample)->get_Duration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSample<D>::KeyFrame(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSample)->put_KeyFrame(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Core_IMediaStreamSample<D>::KeyFrame() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSample)->get_KeyFrame(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSample<D>::Discontinuous(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSample)->put_Discontinuous(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Core_IMediaStreamSample<D>::Discontinuous() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSample)->get_Discontinuous(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface) consume_Windows_Media_Core_IMediaStreamSample2<D>::Direct3D11Surface() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSample2)->get_Direct3D11Surface(&value));
        return winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSampleProtectionProperties<D>::SetKeyIdentifier(array_view<uint8_t const> value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSampleProtectionProperties)->SetKeyIdentifier(value.size(), get_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSampleProtectionProperties<D>::GetKeyIdentifier(com_array<uint8_t>& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSampleProtectionProperties)->GetKeyIdentifier(impl::put_size_abi(value), put_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSampleProtectionProperties<D>::SetInitializationVector(array_view<uint8_t const> value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSampleProtectionProperties)->SetInitializationVector(value.size(), get_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSampleProtectionProperties<D>::GetInitializationVector(com_array<uint8_t>& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSampleProtectionProperties)->GetInitializationVector(impl::put_size_abi(value), put_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSampleProtectionProperties<D>::SetSubSampleMapping(array_view<uint8_t const> value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSampleProtectionProperties)->SetSubSampleMapping(value.size(), get_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSampleProtectionProperties<D>::GetSubSampleMapping(com_array<uint8_t>& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSampleProtectionProperties)->GetSubSampleMapping(impl::put_size_abi(value), put_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaStreamSample) consume_Windows_Media_Core_IMediaStreamSampleStatics<D>::CreateFromBuffer(winrt::Windows::Storage::Streams::IBuffer const& buffer, winrt::Windows::Foundation::TimeSpan const& timestamp) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSampleStatics)->CreateFromBuffer(*(void**)(&buffer), impl::bind_in(timestamp), &value));
        return winrt::Windows::Media::Core::MediaStreamSample{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Core::MediaStreamSample>) consume_Windows_Media_Core_IMediaStreamSampleStatics<D>::CreateFromStreamAsync(winrt::Windows::Storage::Streams::IInputStream const& stream, uint32_t count, winrt::Windows::Foundation::TimeSpan const& timestamp) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSampleStatics)->CreateFromStreamAsync(*(void**)(&stream), count, impl::bind_in(timestamp), &value));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Core::MediaStreamSample>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaStreamSample) consume_Windows_Media_Core_IMediaStreamSampleStatics2<D>::CreateFromDirect3D11Surface(winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& surface, winrt::Windows::Foundation::TimeSpan const& timestamp) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSampleStatics2)->CreateFromDirect3D11Surface(*(void**)(&surface), impl::bind_in(timestamp), &result));
        return winrt::Windows::Media::Core::MediaStreamSample{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_IMediaStreamSource<D>::Closed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaStreamSource, winrt::Windows::Media::Core::MediaStreamSourceClosedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource)->add_Closed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_IMediaStreamSource<D>::Closed_revoker consume_Windows_Media_Core_IMediaStreamSource<D>::Closed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaStreamSource, winrt::Windows::Media::Core::MediaStreamSourceClosedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSource<D>::Closed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource)->remove_Closed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_IMediaStreamSource<D>::Starting(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaStreamSource, winrt::Windows::Media::Core::MediaStreamSourceStartingEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource)->add_Starting(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_IMediaStreamSource<D>::Starting_revoker consume_Windows_Media_Core_IMediaStreamSource<D>::Starting(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaStreamSource, winrt::Windows::Media::Core::MediaStreamSourceStartingEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Starting_revoker>(this, Starting(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSource<D>::Starting(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource)->remove_Starting(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_IMediaStreamSource<D>::Paused(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaStreamSource, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource)->add_Paused(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_IMediaStreamSource<D>::Paused_revoker consume_Windows_Media_Core_IMediaStreamSource<D>::Paused(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaStreamSource, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Paused_revoker>(this, Paused(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSource<D>::Paused(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource)->remove_Paused(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_IMediaStreamSource<D>::SampleRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaStreamSource, winrt::Windows::Media::Core::MediaStreamSourceSampleRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource)->add_SampleRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_IMediaStreamSource<D>::SampleRequested_revoker consume_Windows_Media_Core_IMediaStreamSource<D>::SampleRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaStreamSource, winrt::Windows::Media::Core::MediaStreamSourceSampleRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, SampleRequested_revoker>(this, SampleRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSource<D>::SampleRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource)->remove_SampleRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_IMediaStreamSource<D>::SwitchStreamsRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaStreamSource, winrt::Windows::Media::Core::MediaStreamSourceSwitchStreamsRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource)->add_SwitchStreamsRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_IMediaStreamSource<D>::SwitchStreamsRequested_revoker consume_Windows_Media_Core_IMediaStreamSource<D>::SwitchStreamsRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaStreamSource, winrt::Windows::Media::Core::MediaStreamSourceSwitchStreamsRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, SwitchStreamsRequested_revoker>(this, SwitchStreamsRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSource<D>::SwitchStreamsRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource)->remove_SwitchStreamsRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSource<D>::NotifyError(winrt::Windows::Media::Core::MediaStreamSourceErrorStatus const& errorStatus) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource)->NotifyError(static_cast<int32_t>(errorStatus)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSource<D>::AddStreamDescriptor(winrt::Windows::Media::Core::IMediaStreamDescriptor const& descriptor) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource)->AddStreamDescriptor(*(void**)(&descriptor)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSource<D>::MediaProtectionManager(winrt::Windows::Media::Protection::MediaProtectionManager const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource)->put_MediaProtectionManager(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Protection::MediaProtectionManager) consume_Windows_Media_Core_IMediaStreamSource<D>::MediaProtectionManager() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource)->get_MediaProtectionManager(&value));
        return winrt::Windows::Media::Protection::MediaProtectionManager{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSource<D>::Duration(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource)->put_Duration(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Core_IMediaStreamSource<D>::Duration() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource)->get_Duration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSource<D>::CanSeek(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource)->put_CanSeek(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Core_IMediaStreamSource<D>::CanSeek() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource)->get_CanSeek(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSource<D>::BufferTime(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource)->put_BufferTime(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Core_IMediaStreamSource<D>::BufferTime() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource)->get_BufferTime(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSource<D>::SetBufferedRange(winrt::Windows::Foundation::TimeSpan const& startOffset, winrt::Windows::Foundation::TimeSpan const& endOffset) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource)->SetBufferedRange(impl::bind_in(startOffset), impl::bind_in(endOffset)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::FileProperties::MusicProperties) consume_Windows_Media_Core_IMediaStreamSource<D>::MusicProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource)->get_MusicProperties(&value));
        return winrt::Windows::Storage::FileProperties::MusicProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::FileProperties::VideoProperties) consume_Windows_Media_Core_IMediaStreamSource<D>::VideoProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource)->get_VideoProperties(&value));
        return winrt::Windows::Storage::FileProperties::VideoProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSource<D>::Thumbnail(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource)->put_Thumbnail(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamReference) consume_Windows_Media_Core_IMediaStreamSource<D>::Thumbnail() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource)->get_Thumbnail(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamReference{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSource<D>::AddProtectionKey(winrt::Windows::Media::Core::IMediaStreamDescriptor const& streamDescriptor, array_view<uint8_t const> keyIdentifier, array_view<uint8_t const> licenseData) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource)->AddProtectionKey(*(void**)(&streamDescriptor), keyIdentifier.size(), get_abi(keyIdentifier), licenseData.size(), get_abi(licenseData)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_IMediaStreamSource2<D>::SampleRendered(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaStreamSource, winrt::Windows::Media::Core::MediaStreamSourceSampleRenderedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource2)->add_SampleRendered(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_IMediaStreamSource2<D>::SampleRendered_revoker consume_Windows_Media_Core_IMediaStreamSource2<D>::SampleRendered(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaStreamSource, winrt::Windows::Media::Core::MediaStreamSourceSampleRenderedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, SampleRendered_revoker>(this, SampleRendered(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSource2<D>::SampleRendered(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource2)->remove_SampleRendered(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSource3<D>::MaxSupportedPlaybackRate(winrt::Windows::Foundation::IReference<double> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource3)->put_MaxSupportedPlaybackRate(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<double>) consume_Windows_Media_Core_IMediaStreamSource3<D>::MaxSupportedPlaybackRate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource3)->get_MaxSupportedPlaybackRate(&value));
        return winrt::Windows::Foundation::IReference<double>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSource4<D>::IsLive(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource4)->put_IsLive(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Core_IMediaStreamSource4<D>::IsLive() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSource4)->get_IsLive(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaStreamSourceClosedRequest) consume_Windows_Media_Core_IMediaStreamSourceClosedEventArgs<D>::Request() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSourceClosedEventArgs)->get_Request(&value));
        return winrt::Windows::Media::Core::MediaStreamSourceClosedRequest{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaStreamSourceClosedReason) consume_Windows_Media_Core_IMediaStreamSourceClosedRequest<D>::Reason() const
    {
        winrt::Windows::Media::Core::MediaStreamSourceClosedReason value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSourceClosedRequest)->get_Reason(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaStreamSource) consume_Windows_Media_Core_IMediaStreamSourceFactory<D>::CreateFromDescriptor(winrt::Windows::Media::Core::IMediaStreamDescriptor const& descriptor) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSourceFactory)->CreateFromDescriptor(*(void**)(&descriptor), &result));
        return winrt::Windows::Media::Core::MediaStreamSource{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaStreamSource) consume_Windows_Media_Core_IMediaStreamSourceFactory<D>::CreateFromDescriptors(winrt::Windows::Media::Core::IMediaStreamDescriptor const& descriptor, winrt::Windows::Media::Core::IMediaStreamDescriptor const& descriptor2) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSourceFactory)->CreateFromDescriptors(*(void**)(&descriptor), *(void**)(&descriptor2), &result));
        return winrt::Windows::Media::Core::MediaStreamSource{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Core_IMediaStreamSourceSampleRenderedEventArgs<D>::SampleLag() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSourceSampleRenderedEventArgs)->get_SampleLag(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::IMediaStreamDescriptor) consume_Windows_Media_Core_IMediaStreamSourceSampleRequest<D>::StreamDescriptor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSourceSampleRequest)->get_StreamDescriptor(&value));
        return winrt::Windows::Media::Core::IMediaStreamDescriptor{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaStreamSourceSampleRequestDeferral) consume_Windows_Media_Core_IMediaStreamSourceSampleRequest<D>::GetDeferral() const
    {
        void* deferral{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSourceSampleRequest)->GetDeferral(&deferral));
        return winrt::Windows::Media::Core::MediaStreamSourceSampleRequestDeferral{ deferral, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSourceSampleRequest<D>::Sample(winrt::Windows::Media::Core::MediaStreamSample const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSourceSampleRequest)->put_Sample(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaStreamSample) consume_Windows_Media_Core_IMediaStreamSourceSampleRequest<D>::Sample() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSourceSampleRequest)->get_Sample(&value));
        return winrt::Windows::Media::Core::MediaStreamSample{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSourceSampleRequest<D>::ReportSampleProgress(uint32_t progress) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSourceSampleRequest)->ReportSampleProgress(progress));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSourceSampleRequestDeferral<D>::Complete() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSourceSampleRequestDeferral)->Complete());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaStreamSourceSampleRequest) consume_Windows_Media_Core_IMediaStreamSourceSampleRequestedEventArgs<D>::Request() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSourceSampleRequestedEventArgs)->get_Request(&value));
        return winrt::Windows::Media::Core::MediaStreamSourceSampleRequest{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaStreamSourceStartingRequest) consume_Windows_Media_Core_IMediaStreamSourceStartingEventArgs<D>::Request() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSourceStartingEventArgs)->get_Request(&value));
        return winrt::Windows::Media::Core::MediaStreamSourceStartingRequest{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Media_Core_IMediaStreamSourceStartingRequest<D>::StartPosition() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSourceStartingRequest)->get_StartPosition(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaStreamSourceStartingRequestDeferral) consume_Windows_Media_Core_IMediaStreamSourceStartingRequest<D>::GetDeferral() const
    {
        void* deferral{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSourceStartingRequest)->GetDeferral(&deferral));
        return winrt::Windows::Media::Core::MediaStreamSourceStartingRequestDeferral{ deferral, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSourceStartingRequest<D>::SetActualStartPosition(winrt::Windows::Foundation::TimeSpan const& position) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSourceStartingRequest)->SetActualStartPosition(impl::bind_in(position)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSourceStartingRequestDeferral<D>::Complete() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSourceStartingRequestDeferral)->Complete());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::IMediaStreamDescriptor) consume_Windows_Media_Core_IMediaStreamSourceSwitchStreamsRequest<D>::OldStreamDescriptor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequest)->get_OldStreamDescriptor(&value));
        return winrt::Windows::Media::Core::IMediaStreamDescriptor{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::IMediaStreamDescriptor) consume_Windows_Media_Core_IMediaStreamSourceSwitchStreamsRequest<D>::NewStreamDescriptor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequest)->get_NewStreamDescriptor(&value));
        return winrt::Windows::Media::Core::IMediaStreamDescriptor{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaStreamSourceSwitchStreamsRequestDeferral) consume_Windows_Media_Core_IMediaStreamSourceSwitchStreamsRequest<D>::GetDeferral() const
    {
        void* deferral{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequest)->GetDeferral(&deferral));
        return winrt::Windows::Media::Core::MediaStreamSourceSwitchStreamsRequestDeferral{ deferral, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaStreamSourceSwitchStreamsRequestDeferral<D>::Complete() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequestDeferral)->Complete());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaStreamSourceSwitchStreamsRequest) consume_Windows_Media_Core_IMediaStreamSourceSwitchStreamsRequestedEventArgs<D>::Request() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequestedEventArgs)->get_Request(&value));
        return winrt::Windows::Media::Core::MediaStreamSourceSwitchStreamsRequest{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_IMediaTrack<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaTrack)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_IMediaTrack<D>::Language() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaTrack)->get_Language(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaTrackKind) consume_Windows_Media_Core_IMediaTrack<D>::TrackKind() const
    {
        winrt::Windows::Media::Core::MediaTrackKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaTrack)->get_TrackKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMediaTrack<D>::Label(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaTrack)->put_Label(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_IMediaTrack<D>::Label() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMediaTrack)->get_Label(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_IMseSourceBuffer<D>::UpdateStarting(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseSourceBuffer, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBuffer)->add_UpdateStarting(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_IMseSourceBuffer<D>::UpdateStarting_revoker consume_Windows_Media_Core_IMseSourceBuffer<D>::UpdateStarting(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseSourceBuffer, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, UpdateStarting_revoker>(this, UpdateStarting(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMseSourceBuffer<D>::UpdateStarting(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBuffer)->remove_UpdateStarting(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_IMseSourceBuffer<D>::Updated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseSourceBuffer, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBuffer)->add_Updated(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_IMseSourceBuffer<D>::Updated_revoker consume_Windows_Media_Core_IMseSourceBuffer<D>::Updated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseSourceBuffer, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Updated_revoker>(this, Updated(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMseSourceBuffer<D>::Updated(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBuffer)->remove_Updated(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_IMseSourceBuffer<D>::UpdateEnded(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseSourceBuffer, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBuffer)->add_UpdateEnded(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_IMseSourceBuffer<D>::UpdateEnded_revoker consume_Windows_Media_Core_IMseSourceBuffer<D>::UpdateEnded(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseSourceBuffer, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, UpdateEnded_revoker>(this, UpdateEnded(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMseSourceBuffer<D>::UpdateEnded(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBuffer)->remove_UpdateEnded(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_IMseSourceBuffer<D>::ErrorOccurred(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseSourceBuffer, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBuffer)->add_ErrorOccurred(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_IMseSourceBuffer<D>::ErrorOccurred_revoker consume_Windows_Media_Core_IMseSourceBuffer<D>::ErrorOccurred(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseSourceBuffer, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ErrorOccurred_revoker>(this, ErrorOccurred(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMseSourceBuffer<D>::ErrorOccurred(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBuffer)->remove_ErrorOccurred(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_IMseSourceBuffer<D>::Aborted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseSourceBuffer, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBuffer)->add_Aborted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_IMseSourceBuffer<D>::Aborted_revoker consume_Windows_Media_Core_IMseSourceBuffer<D>::Aborted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseSourceBuffer, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Aborted_revoker>(this, Aborted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMseSourceBuffer<D>::Aborted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBuffer)->remove_Aborted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MseAppendMode) consume_Windows_Media_Core_IMseSourceBuffer<D>::Mode() const
    {
        winrt::Windows::Media::Core::MseAppendMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBuffer)->get_Mode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMseSourceBuffer<D>::Mode(winrt::Windows::Media::Core::MseAppendMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBuffer)->put_Mode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Core_IMseSourceBuffer<D>::IsUpdating() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBuffer)->get_IsUpdating(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Core::MseTimeRange>) consume_Windows_Media_Core_IMseSourceBuffer<D>::Buffered() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBuffer)->get_Buffered(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Core::MseTimeRange>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Core_IMseSourceBuffer<D>::TimestampOffset() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBuffer)->get_TimestampOffset(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMseSourceBuffer<D>::TimestampOffset(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBuffer)->put_TimestampOffset(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Core_IMseSourceBuffer<D>::AppendWindowStart() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBuffer)->get_AppendWindowStart(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMseSourceBuffer<D>::AppendWindowStart(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBuffer)->put_AppendWindowStart(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Media_Core_IMseSourceBuffer<D>::AppendWindowEnd() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBuffer)->get_AppendWindowEnd(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMseSourceBuffer<D>::AppendWindowEnd(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBuffer)->put_AppendWindowEnd(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMseSourceBuffer<D>::AppendBuffer(winrt::Windows::Storage::Streams::IBuffer const& buffer) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBuffer)->AppendBuffer(*(void**)(&buffer)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMseSourceBuffer<D>::AppendStream(winrt::Windows::Storage::Streams::IInputStream const& stream) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBuffer)->AppendStream(*(void**)(&stream)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMseSourceBuffer<D>::AppendStream(winrt::Windows::Storage::Streams::IInputStream const& stream, uint64_t maxSize) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBuffer)->AppendStreamMaxSize(*(void**)(&stream), maxSize));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMseSourceBuffer<D>::Abort() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBuffer)->Abort());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMseSourceBuffer<D>::Remove(winrt::Windows::Foundation::TimeSpan const& start, winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const& end) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBuffer)->Remove(impl::bind_in(start), *(void**)(&end)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_IMseSourceBufferList<D>::SourceBufferAdded(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseSourceBufferList, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBufferList)->add_SourceBufferAdded(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_IMseSourceBufferList<D>::SourceBufferAdded_revoker consume_Windows_Media_Core_IMseSourceBufferList<D>::SourceBufferAdded(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseSourceBufferList, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, SourceBufferAdded_revoker>(this, SourceBufferAdded(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMseSourceBufferList<D>::SourceBufferAdded(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBufferList)->remove_SourceBufferAdded(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_IMseSourceBufferList<D>::SourceBufferRemoved(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseSourceBufferList, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBufferList)->add_SourceBufferRemoved(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_IMseSourceBufferList<D>::SourceBufferRemoved_revoker consume_Windows_Media_Core_IMseSourceBufferList<D>::SourceBufferRemoved(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseSourceBufferList, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, SourceBufferRemoved_revoker>(this, SourceBufferRemoved(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMseSourceBufferList<D>::SourceBufferRemoved(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBufferList)->remove_SourceBufferRemoved(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Core::MseSourceBuffer>) consume_Windows_Media_Core_IMseSourceBufferList<D>::Buffers() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseSourceBufferList)->get_Buffers(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Core::MseSourceBuffer>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_IMseStreamSource<D>::Opened(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseStreamSource, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseStreamSource)->add_Opened(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_IMseStreamSource<D>::Opened_revoker consume_Windows_Media_Core_IMseStreamSource<D>::Opened(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseStreamSource, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Opened_revoker>(this, Opened(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMseStreamSource<D>::Opened(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseStreamSource)->remove_Opened(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_IMseStreamSource<D>::Ended(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseStreamSource, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseStreamSource)->add_Ended(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_IMseStreamSource<D>::Ended_revoker consume_Windows_Media_Core_IMseStreamSource<D>::Ended(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseStreamSource, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Ended_revoker>(this, Ended(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMseStreamSource<D>::Ended(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseStreamSource)->remove_Ended(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_IMseStreamSource<D>::Closed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseStreamSource, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseStreamSource)->add_Closed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_IMseStreamSource<D>::Closed_revoker consume_Windows_Media_Core_IMseStreamSource<D>::Closed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseStreamSource, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, Closed_revoker>(this, Closed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMseStreamSource<D>::Closed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseStreamSource)->remove_Closed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MseSourceBufferList) consume_Windows_Media_Core_IMseStreamSource<D>::SourceBuffers() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseStreamSource)->get_SourceBuffers(&value));
        return winrt::Windows::Media::Core::MseSourceBufferList{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MseSourceBufferList) consume_Windows_Media_Core_IMseStreamSource<D>::ActiveSourceBuffers() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseStreamSource)->get_ActiveSourceBuffers(&value));
        return winrt::Windows::Media::Core::MseSourceBufferList{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MseReadyState) consume_Windows_Media_Core_IMseStreamSource<D>::ReadyState() const
    {
        winrt::Windows::Media::Core::MseReadyState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseStreamSource)->get_ReadyState(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Media_Core_IMseStreamSource<D>::Duration() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseStreamSource)->get_Duration(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMseStreamSource<D>::Duration(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseStreamSource)->put_Duration(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MseSourceBuffer) consume_Windows_Media_Core_IMseStreamSource<D>::AddSourceBuffer(param::hstring const& mimeType) const
    {
        void* buffer{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseStreamSource)->AddSourceBuffer(*(void**)(&mimeType), &buffer));
        return winrt::Windows::Media::Core::MseSourceBuffer{ buffer, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMseStreamSource<D>::RemoveSourceBuffer(winrt::Windows::Media::Core::MseSourceBuffer const& buffer) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseStreamSource)->RemoveSourceBuffer(*(void**)(&buffer)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMseStreamSource<D>::EndOfStream(winrt::Windows::Media::Core::MseEndOfStreamStatus const& status) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseStreamSource)->EndOfStream(static_cast<int32_t>(status)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Media::Core::MseTimeRange>) consume_Windows_Media_Core_IMseStreamSource2<D>::LiveSeekableRange() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseStreamSource2)->get_LiveSeekableRange(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Media::Core::MseTimeRange>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IMseStreamSource2<D>::LiveSeekableRange(winrt::Windows::Foundation::IReference<winrt::Windows::Media::Core::MseTimeRange> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseStreamSource2)->put_LiveSeekableRange(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Core_IMseStreamSourceStatics<D>::IsContentTypeSupported(param::hstring const& contentType) const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IMseStreamSourceStatics)->IsContentTypeSupported(*(void**)(&contentType), &value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::HighDynamicRangeControl) consume_Windows_Media_Core_ISceneAnalysisEffect<D>::HighDynamicRangeAnalyzer() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ISceneAnalysisEffect)->get_HighDynamicRangeAnalyzer(&value));
        return winrt::Windows::Media::Core::HighDynamicRangeControl{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ISceneAnalysisEffect<D>::DesiredAnalysisInterval(winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ISceneAnalysisEffect)->put_DesiredAnalysisInterval(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Core_ISceneAnalysisEffect<D>::DesiredAnalysisInterval() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ISceneAnalysisEffect)->get_DesiredAnalysisInterval(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_ISceneAnalysisEffect<D>::SceneAnalyzed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::SceneAnalysisEffect, winrt::Windows::Media::Core::SceneAnalyzedEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ISceneAnalysisEffect)->add_SceneAnalyzed(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Media_Core_ISceneAnalysisEffect<D>::SceneAnalyzed_revoker consume_Windows_Media_Core_ISceneAnalysisEffect<D>::SceneAnalyzed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::SceneAnalysisEffect, winrt::Windows::Media::Core::SceneAnalyzedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, SceneAnalyzed_revoker>(this, SceneAnalyzed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ISceneAnalysisEffect<D>::SceneAnalyzed(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ISceneAnalysisEffect)->remove_SceneAnalyzed(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::CapturedFrameControlValues) consume_Windows_Media_Core_ISceneAnalysisEffectFrame<D>::FrameControlValues() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ISceneAnalysisEffectFrame)->get_FrameControlValues(&value));
        return winrt::Windows::Media::Capture::CapturedFrameControlValues{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::HighDynamicRangeOutput) consume_Windows_Media_Core_ISceneAnalysisEffectFrame<D>::HighDynamicRange() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ISceneAnalysisEffectFrame)->get_HighDynamicRange(&value));
        return winrt::Windows::Media::Core::HighDynamicRangeOutput{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::SceneAnalysisRecommendation) consume_Windows_Media_Core_ISceneAnalysisEffectFrame2<D>::AnalysisRecommendation() const
    {
        winrt::Windows::Media::Core::SceneAnalysisRecommendation value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ISceneAnalysisEffectFrame2)->get_AnalysisRecommendation(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::SceneAnalysisEffectFrame) consume_Windows_Media_Core_ISceneAnalyzedEventArgs<D>::ResultFrame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ISceneAnalyzedEventArgs)->get_ResultFrame(&value));
        return winrt::Windows::Media::Core::SceneAnalysisEffectFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_ISingleSelectMediaTrackList<D>::SelectedIndexChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::ISingleSelectMediaTrackList, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ISingleSelectMediaTrackList)->add_SelectedIndexChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_ISingleSelectMediaTrackList<D>::SelectedIndexChanged_revoker consume_Windows_Media_Core_ISingleSelectMediaTrackList<D>::SelectedIndexChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::ISingleSelectMediaTrackList, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, SelectedIndexChanged_revoker>(this, SelectedIndexChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ISingleSelectMediaTrackList<D>::SelectedIndexChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ISingleSelectMediaTrackList)->remove_SelectedIndexChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ISingleSelectMediaTrackList<D>::SelectedIndex(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ISingleSelectMediaTrackList)->put_SelectedIndex(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_Core_ISingleSelectMediaTrackList<D>::SelectedIndex() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ISingleSelectMediaTrackList)->get_SelectedIndex(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ISpeechCue<D>::Text() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ISpeechCue)->get_Text(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ISpeechCue<D>::Text(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ISpeechCue)->put_Text(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_Media_Core_ISpeechCue<D>::StartPositionInInput() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ISpeechCue)->get_StartPositionInInput(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ISpeechCue<D>::StartPositionInInput(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ISpeechCue)->put_StartPositionInInput(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_Media_Core_ISpeechCue<D>::EndPositionInInput() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ISpeechCue)->get_EndPositionInInput(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ISpeechCue<D>::EndPositionInInput(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ISpeechCue)->put_EndPositionInInput(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::TimedMetadataEncodingProperties) consume_Windows_Media_Core_ITimedMetadataStreamDescriptor<D>::EncodingProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedMetadataStreamDescriptor)->get_EncodingProperties(&value));
        return winrt::Windows::Media::MediaProperties::TimedMetadataEncodingProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedMetadataStreamDescriptor) consume_Windows_Media_Core_ITimedMetadataStreamDescriptor<D>::Copy() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedMetadataStreamDescriptor)->Copy(&result));
        return winrt::Windows::Media::Core::TimedMetadataStreamDescriptor{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedMetadataStreamDescriptor) consume_Windows_Media_Core_ITimedMetadataStreamDescriptorFactory<D>::Create(winrt::Windows::Media::MediaProperties::TimedMetadataEncodingProperties const& encodingProperties) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedMetadataStreamDescriptorFactory)->Create(*(void**)(&encodingProperties), &result));
        return winrt::Windows::Media::Core::TimedMetadataStreamDescriptor{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_ITimedMetadataTrack<D>::CueEntered(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::TimedMetadataTrack, winrt::Windows::Media::Core::MediaCueEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedMetadataTrack)->add_CueEntered(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_ITimedMetadataTrack<D>::CueEntered_revoker consume_Windows_Media_Core_ITimedMetadataTrack<D>::CueEntered(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::TimedMetadataTrack, winrt::Windows::Media::Core::MediaCueEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, CueEntered_revoker>(this, CueEntered(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedMetadataTrack<D>::CueEntered(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedMetadataTrack)->remove_CueEntered(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_ITimedMetadataTrack<D>::CueExited(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::TimedMetadataTrack, winrt::Windows::Media::Core::MediaCueEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedMetadataTrack)->add_CueExited(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_ITimedMetadataTrack<D>::CueExited_revoker consume_Windows_Media_Core_ITimedMetadataTrack<D>::CueExited(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::TimedMetadataTrack, winrt::Windows::Media::Core::MediaCueEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, CueExited_revoker>(this, CueExited(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedMetadataTrack<D>::CueExited(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedMetadataTrack)->remove_CueExited(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_ITimedMetadataTrack<D>::TrackFailed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::TimedMetadataTrack, winrt::Windows::Media::Core::TimedMetadataTrackFailedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedMetadataTrack)->add_TrackFailed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_ITimedMetadataTrack<D>::TrackFailed_revoker consume_Windows_Media_Core_ITimedMetadataTrack<D>::TrackFailed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::TimedMetadataTrack, winrt::Windows::Media::Core::TimedMetadataTrackFailedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, TrackFailed_revoker>(this, TrackFailed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedMetadataTrack<D>::TrackFailed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedMetadataTrack)->remove_TrackFailed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Core::IMediaCue>) consume_Windows_Media_Core_ITimedMetadataTrack<D>::Cues() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedMetadataTrack)->get_Cues(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Core::IMediaCue>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Core::IMediaCue>) consume_Windows_Media_Core_ITimedMetadataTrack<D>::ActiveCues() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedMetadataTrack)->get_ActiveCues(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Core::IMediaCue>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedMetadataKind) consume_Windows_Media_Core_ITimedMetadataTrack<D>::TimedMetadataKind() const
    {
        winrt::Windows::Media::Core::TimedMetadataKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedMetadataTrack)->get_TimedMetadataKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ITimedMetadataTrack<D>::DispatchType() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedMetadataTrack)->get_DispatchType(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedMetadataTrack<D>::AddCue(winrt::Windows::Media::Core::IMediaCue const& cue) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedMetadataTrack)->AddCue(*(void**)(&cue)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedMetadataTrack<D>::RemoveCue(winrt::Windows::Media::Core::IMediaCue const& cue) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedMetadataTrack)->RemoveCue(*(void**)(&cue)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackItem) consume_Windows_Media_Core_ITimedMetadataTrack2<D>::PlaybackItem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedMetadataTrack2)->get_PlaybackItem(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackItem{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ITimedMetadataTrack2<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedMetadataTrack2)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedMetadataTrackErrorCode) consume_Windows_Media_Core_ITimedMetadataTrackError<D>::ErrorCode() const
    {
        winrt::Windows::Media::Core::TimedMetadataTrackErrorCode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedMetadataTrackError)->get_ErrorCode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Media_Core_ITimedMetadataTrackError<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedMetadataTrackError)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedMetadataTrack) consume_Windows_Media_Core_ITimedMetadataTrackFactory<D>::Create(param::hstring const& id, param::hstring const& language, winrt::Windows::Media::Core::TimedMetadataKind const& kind) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedMetadataTrackFactory)->Create(*(void**)(&id), *(void**)(&language), static_cast<int32_t>(kind), &value));
        return winrt::Windows::Media::Core::TimedMetadataTrack{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedMetadataTrackError) consume_Windows_Media_Core_ITimedMetadataTrackFailedEventArgs<D>::Error() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedMetadataTrackFailedEventArgs)->get_Error(&value));
        return winrt::Windows::Media::Core::TimedMetadataTrackError{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Core::TimedMetadataTrack>) consume_Windows_Media_Core_ITimedMetadataTrackProvider<D>::TimedMetadataTracks() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedMetadataTrackProvider)->get_TimedMetadataTracks(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Core::TimedMetadataTrack>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextBoutenType) consume_Windows_Media_Core_ITimedTextBouten<D>::Type() const
    {
        winrt::Windows::Media::Core::TimedTextBoutenType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextBouten)->get_Type(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextBouten<D>::Type(winrt::Windows::Media::Core::TimedTextBoutenType const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextBouten)->put_Type(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_Media_Core_ITimedTextBouten<D>::Color() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextBouten)->get_Color(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextBouten<D>::Color(winrt::Windows::UI::Color const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextBouten)->put_Color(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextBoutenPosition) consume_Windows_Media_Core_ITimedTextBouten<D>::Position() const
    {
        winrt::Windows::Media::Core::TimedTextBoutenPosition value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextBouten)->get_Position(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextBouten<D>::Position(winrt::Windows::Media::Core::TimedTextBoutenPosition const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextBouten)->put_Position(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextRegion) consume_Windows_Media_Core_ITimedTextCue<D>::CueRegion() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextCue)->get_CueRegion(&value));
        return winrt::Windows::Media::Core::TimedTextRegion{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextCue<D>::CueRegion(winrt::Windows::Media::Core::TimedTextRegion const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextCue)->put_CueRegion(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextStyle) consume_Windows_Media_Core_ITimedTextCue<D>::CueStyle() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextCue)->get_CueStyle(&value));
        return winrt::Windows::Media::Core::TimedTextStyle{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextCue<D>::CueStyle(winrt::Windows::Media::Core::TimedTextStyle const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextCue)->put_CueStyle(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Media::Core::TimedTextLine>) consume_Windows_Media_Core_ITimedTextCue<D>::Lines() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextCue)->get_Lines(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Media::Core::TimedTextLine>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ITimedTextLine<D>::Text() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextLine)->get_Text(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextLine<D>::Text(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextLine)->put_Text(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Media::Core::TimedTextSubformat>) consume_Windows_Media_Core_ITimedTextLine<D>::Subformats() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextLine)->get_Subformats(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Media::Core::TimedTextSubformat>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ITimedTextRegion<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRegion)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextRegion<D>::Name(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRegion)->put_Name(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextPoint) consume_Windows_Media_Core_ITimedTextRegion<D>::Position() const
    {
        winrt::Windows::Media::Core::TimedTextPoint value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRegion)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextRegion<D>::Position(winrt::Windows::Media::Core::TimedTextPoint const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRegion)->put_Position(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextSize) consume_Windows_Media_Core_ITimedTextRegion<D>::Extent() const
    {
        winrt::Windows::Media::Core::TimedTextSize value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRegion)->get_Extent(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextRegion<D>::Extent(winrt::Windows::Media::Core::TimedTextSize const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRegion)->put_Extent(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_Media_Core_ITimedTextRegion<D>::Background() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRegion)->get_Background(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextRegion<D>::Background(winrt::Windows::UI::Color const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRegion)->put_Background(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextWritingMode) consume_Windows_Media_Core_ITimedTextRegion<D>::WritingMode() const
    {
        winrt::Windows::Media::Core::TimedTextWritingMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRegion)->get_WritingMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextRegion<D>::WritingMode(winrt::Windows::Media::Core::TimedTextWritingMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRegion)->put_WritingMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextDisplayAlignment) consume_Windows_Media_Core_ITimedTextRegion<D>::DisplayAlignment() const
    {
        winrt::Windows::Media::Core::TimedTextDisplayAlignment value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRegion)->get_DisplayAlignment(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextRegion<D>::DisplayAlignment(winrt::Windows::Media::Core::TimedTextDisplayAlignment const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRegion)->put_DisplayAlignment(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextDouble) consume_Windows_Media_Core_ITimedTextRegion<D>::LineHeight() const
    {
        winrt::Windows::Media::Core::TimedTextDouble value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRegion)->get_LineHeight(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextRegion<D>::LineHeight(winrt::Windows::Media::Core::TimedTextDouble const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRegion)->put_LineHeight(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Core_ITimedTextRegion<D>::IsOverflowClipped() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRegion)->get_IsOverflowClipped(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextRegion<D>::IsOverflowClipped(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRegion)->put_IsOverflowClipped(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextPadding) consume_Windows_Media_Core_ITimedTextRegion<D>::Padding() const
    {
        winrt::Windows::Media::Core::TimedTextPadding value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRegion)->get_Padding(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextRegion<D>::Padding(winrt::Windows::Media::Core::TimedTextPadding const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRegion)->put_Padding(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextWrapping) consume_Windows_Media_Core_ITimedTextRegion<D>::TextWrapping() const
    {
        winrt::Windows::Media::Core::TimedTextWrapping value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRegion)->get_TextWrapping(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextRegion<D>::TextWrapping(winrt::Windows::Media::Core::TimedTextWrapping const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRegion)->put_TextWrapping(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_Core_ITimedTextRegion<D>::ZIndex() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRegion)->get_ZIndex(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextRegion<D>::ZIndex(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRegion)->put_ZIndex(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextScrollMode) consume_Windows_Media_Core_ITimedTextRegion<D>::ScrollMode() const
    {
        winrt::Windows::Media::Core::TimedTextScrollMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRegion)->get_ScrollMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextRegion<D>::ScrollMode(winrt::Windows::Media::Core::TimedTextScrollMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRegion)->put_ScrollMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ITimedTextRuby<D>::Text() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRuby)->get_Text(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextRuby<D>::Text(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRuby)->put_Text(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextRubyPosition) consume_Windows_Media_Core_ITimedTextRuby<D>::Position() const
    {
        winrt::Windows::Media::Core::TimedTextRubyPosition value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRuby)->get_Position(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextRuby<D>::Position(winrt::Windows::Media::Core::TimedTextRubyPosition const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRuby)->put_Position(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextRubyAlign) consume_Windows_Media_Core_ITimedTextRuby<D>::Align() const
    {
        winrt::Windows::Media::Core::TimedTextRubyAlign value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRuby)->get_Align(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextRuby<D>::Align(winrt::Windows::Media::Core::TimedTextRubyAlign const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRuby)->put_Align(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextRubyReserve) consume_Windows_Media_Core_ITimedTextRuby<D>::Reserve() const
    {
        winrt::Windows::Media::Core::TimedTextRubyReserve value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRuby)->get_Reserve(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextRuby<D>::Reserve(winrt::Windows::Media::Core::TimedTextRubyReserve const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextRuby)->put_Reserve(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_ITimedTextSource<D>::Resolved(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::TimedTextSource, winrt::Windows::Media::Core::TimedTextSourceResolveResultEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextSource)->add_Resolved(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_ITimedTextSource<D>::Resolved_revoker consume_Windows_Media_Core_ITimedTextSource<D>::Resolved(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::TimedTextSource, winrt::Windows::Media::Core::TimedTextSourceResolveResultEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, Resolved_revoker>(this, Resolved(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextSource<D>::Resolved(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextSource)->remove_Resolved(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedMetadataTrackError) consume_Windows_Media_Core_ITimedTextSourceResolveResultEventArgs<D>::Error() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextSourceResolveResultEventArgs)->get_Error(&value));
        return winrt::Windows::Media::Core::TimedMetadataTrackError{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Core::TimedMetadataTrack>) consume_Windows_Media_Core_ITimedTextSourceResolveResultEventArgs<D>::Tracks() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextSourceResolveResultEventArgs)->get_Tracks(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Core::TimedMetadataTrack>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextSource) consume_Windows_Media_Core_ITimedTextSourceStatics<D>::CreateFromStream(winrt::Windows::Storage::Streams::IRandomAccessStream const& stream) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextSourceStatics)->CreateFromStream(*(void**)(&stream), &value));
        return winrt::Windows::Media::Core::TimedTextSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextSource) consume_Windows_Media_Core_ITimedTextSourceStatics<D>::CreateFromUri(winrt::Windows::Foundation::Uri const& uri) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextSourceStatics)->CreateFromUri(*(void**)(&uri), &value));
        return winrt::Windows::Media::Core::TimedTextSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextSource) consume_Windows_Media_Core_ITimedTextSourceStatics<D>::CreateFromStream(winrt::Windows::Storage::Streams::IRandomAccessStream const& stream, param::hstring const& defaultLanguage) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextSourceStatics)->CreateFromStreamWithLanguage(*(void**)(&stream), *(void**)(&defaultLanguage), &value));
        return winrt::Windows::Media::Core::TimedTextSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextSource) consume_Windows_Media_Core_ITimedTextSourceStatics<D>::CreateFromUri(winrt::Windows::Foundation::Uri const& uri, param::hstring const& defaultLanguage) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextSourceStatics)->CreateFromUriWithLanguage(*(void**)(&uri), *(void**)(&defaultLanguage), &value));
        return winrt::Windows::Media::Core::TimedTextSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextSource) consume_Windows_Media_Core_ITimedTextSourceStatics2<D>::CreateFromStreamWithIndex(winrt::Windows::Storage::Streams::IRandomAccessStream const& stream, winrt::Windows::Storage::Streams::IRandomAccessStream const& indexStream) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextSourceStatics2)->CreateFromStreamWithIndex(*(void**)(&stream), *(void**)(&indexStream), &result));
        return winrt::Windows::Media::Core::TimedTextSource{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextSource) consume_Windows_Media_Core_ITimedTextSourceStatics2<D>::CreateFromUriWithIndex(winrt::Windows::Foundation::Uri const& uri, winrt::Windows::Foundation::Uri const& indexUri) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextSourceStatics2)->CreateFromUriWithIndex(*(void**)(&uri), *(void**)(&indexUri), &result));
        return winrt::Windows::Media::Core::TimedTextSource{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextSource) consume_Windows_Media_Core_ITimedTextSourceStatics2<D>::CreateFromStreamWithIndex(winrt::Windows::Storage::Streams::IRandomAccessStream const& stream, winrt::Windows::Storage::Streams::IRandomAccessStream const& indexStream, param::hstring const& defaultLanguage) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextSourceStatics2)->CreateFromStreamWithIndexAndLanguage(*(void**)(&stream), *(void**)(&indexStream), *(void**)(&defaultLanguage), &result));
        return winrt::Windows::Media::Core::TimedTextSource{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextSource) consume_Windows_Media_Core_ITimedTextSourceStatics2<D>::CreateFromUriWithIndex(winrt::Windows::Foundation::Uri const& uri, winrt::Windows::Foundation::Uri const& indexUri, param::hstring const& defaultLanguage) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextSourceStatics2)->CreateFromUriWithIndexAndLanguage(*(void**)(&uri), *(void**)(&indexUri), *(void**)(&defaultLanguage), &result));
        return winrt::Windows::Media::Core::TimedTextSource{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ITimedTextStyle<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextStyle<D>::Name(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle)->put_Name(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_ITimedTextStyle<D>::FontFamily() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle)->get_FontFamily(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextStyle<D>::FontFamily(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle)->put_FontFamily(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextDouble) consume_Windows_Media_Core_ITimedTextStyle<D>::FontSize() const
    {
        winrt::Windows::Media::Core::TimedTextDouble value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle)->get_FontSize(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextStyle<D>::FontSize(winrt::Windows::Media::Core::TimedTextDouble const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle)->put_FontSize(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextWeight) consume_Windows_Media_Core_ITimedTextStyle<D>::FontWeight() const
    {
        winrt::Windows::Media::Core::TimedTextWeight value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle)->get_FontWeight(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextStyle<D>::FontWeight(winrt::Windows::Media::Core::TimedTextWeight const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle)->put_FontWeight(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_Media_Core_ITimedTextStyle<D>::Foreground() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle)->get_Foreground(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextStyle<D>::Foreground(winrt::Windows::UI::Color const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle)->put_Foreground(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_Media_Core_ITimedTextStyle<D>::Background() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle)->get_Background(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextStyle<D>::Background(winrt::Windows::UI::Color const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle)->put_Background(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Core_ITimedTextStyle<D>::IsBackgroundAlwaysShown() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle)->get_IsBackgroundAlwaysShown(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextStyle<D>::IsBackgroundAlwaysShown(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle)->put_IsBackgroundAlwaysShown(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextFlowDirection) consume_Windows_Media_Core_ITimedTextStyle<D>::FlowDirection() const
    {
        winrt::Windows::Media::Core::TimedTextFlowDirection value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle)->get_FlowDirection(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextStyle<D>::FlowDirection(winrt::Windows::Media::Core::TimedTextFlowDirection const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle)->put_FlowDirection(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextLineAlignment) consume_Windows_Media_Core_ITimedTextStyle<D>::LineAlignment() const
    {
        winrt::Windows::Media::Core::TimedTextLineAlignment value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle)->get_LineAlignment(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextStyle<D>::LineAlignment(winrt::Windows::Media::Core::TimedTextLineAlignment const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle)->put_LineAlignment(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_Media_Core_ITimedTextStyle<D>::OutlineColor() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle)->get_OutlineColor(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextStyle<D>::OutlineColor(winrt::Windows::UI::Color const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle)->put_OutlineColor(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextDouble) consume_Windows_Media_Core_ITimedTextStyle<D>::OutlineThickness() const
    {
        winrt::Windows::Media::Core::TimedTextDouble value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle)->get_OutlineThickness(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextStyle<D>::OutlineThickness(winrt::Windows::Media::Core::TimedTextDouble const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle)->put_OutlineThickness(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextDouble) consume_Windows_Media_Core_ITimedTextStyle<D>::OutlineRadius() const
    {
        winrt::Windows::Media::Core::TimedTextDouble value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle)->get_OutlineRadius(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextStyle<D>::OutlineRadius(winrt::Windows::Media::Core::TimedTextDouble const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle)->put_OutlineRadius(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextFontStyle) consume_Windows_Media_Core_ITimedTextStyle2<D>::FontStyle() const
    {
        winrt::Windows::Media::Core::TimedTextFontStyle value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle2)->get_FontStyle(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextStyle2<D>::FontStyle(winrt::Windows::Media::Core::TimedTextFontStyle const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle2)->put_FontStyle(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Core_ITimedTextStyle2<D>::IsUnderlineEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle2)->get_IsUnderlineEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextStyle2<D>::IsUnderlineEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle2)->put_IsUnderlineEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Core_ITimedTextStyle2<D>::IsLineThroughEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle2)->get_IsLineThroughEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextStyle2<D>::IsLineThroughEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle2)->put_IsLineThroughEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Core_ITimedTextStyle2<D>::IsOverlineEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle2)->get_IsOverlineEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextStyle2<D>::IsOverlineEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle2)->put_IsOverlineEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextRuby) consume_Windows_Media_Core_ITimedTextStyle3<D>::Ruby() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle3)->get_Ruby(&value));
        return winrt::Windows::Media::Core::TimedTextRuby{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextBouten) consume_Windows_Media_Core_ITimedTextStyle3<D>::Bouten() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle3)->get_Bouten(&value));
        return winrt::Windows::Media::Core::TimedTextBouten{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Core_ITimedTextStyle3<D>::IsTextCombined() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle3)->get_IsTextCombined(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextStyle3<D>::IsTextCombined(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle3)->put_IsTextCombined(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Core_ITimedTextStyle3<D>::FontAngleInDegrees() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle3)->get_FontAngleInDegrees(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextStyle3<D>::FontAngleInDegrees(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextStyle3)->put_FontAngleInDegrees(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_Core_ITimedTextSubformat<D>::StartIndex() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextSubformat)->get_StartIndex(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextSubformat<D>::StartIndex(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextSubformat)->put_StartIndex(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_Core_ITimedTextSubformat<D>::Length() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextSubformat)->get_Length(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextSubformat<D>::Length(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextSubformat)->put_Length(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::TimedTextStyle) consume_Windows_Media_Core_ITimedTextSubformat<D>::SubformatStyle() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextSubformat)->get_SubformatStyle(&value));
        return winrt::Windows::Media::Core::TimedTextStyle{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_ITimedTextSubformat<D>::SubformatStyle(winrt::Windows::Media::Core::TimedTextStyle const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::ITimedTextSubformat)->put_SubformatStyle(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IVideoStabilizationEffect<D>::Enabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IVideoStabilizationEffect)->put_Enabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Core_IVideoStabilizationEffect<D>::Enabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IVideoStabilizationEffect)->get_Enabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_IVideoStabilizationEffect<D>::EnabledChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::VideoStabilizationEffect, winrt::Windows::Media::Core::VideoStabilizationEffectEnabledChangedEventArgs> const& handler) const
    {
        winrt::event_token cookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IVideoStabilizationEffect)->add_EnabledChanged(*(void**)(&handler), put_abi(cookie)));
        return cookie;
    }
    template <typename D> typename consume_Windows_Media_Core_IVideoStabilizationEffect<D>::EnabledChanged_revoker consume_Windows_Media_Core_IVideoStabilizationEffect<D>::EnabledChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::VideoStabilizationEffect, winrt::Windows::Media::Core::VideoStabilizationEffectEnabledChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, EnabledChanged_revoker>(this, EnabledChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IVideoStabilizationEffect<D>::EnabledChanged(winrt::event_token const& cookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IVideoStabilizationEffect)->remove_EnabledChanged(impl::bind_in(cookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Capture::VideoStreamConfiguration) consume_Windows_Media_Core_IVideoStabilizationEffect<D>::GetRecommendedStreamConfiguration(winrt::Windows::Media::Devices::VideoDeviceController const& controller, winrt::Windows::Media::MediaProperties::VideoEncodingProperties const& desiredProperties) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IVideoStabilizationEffect)->GetRecommendedStreamConfiguration(*(void**)(&controller), *(void**)(&desiredProperties), &value));
        return winrt::Windows::Media::Capture::VideoStreamConfiguration{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::VideoStabilizationEffectEnabledChangedReason) consume_Windows_Media_Core_IVideoStabilizationEffectEnabledChangedEventArgs<D>::Reason() const
    {
        winrt::Windows::Media::Core::VideoStabilizationEffectEnabledChangedReason value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IVideoStabilizationEffectEnabledChangedEventArgs)->get_Reason(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::VideoEncodingProperties) consume_Windows_Media_Core_IVideoStreamDescriptor<D>::EncodingProperties() const
    {
        void* encodingProperties{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IVideoStreamDescriptor)->get_EncodingProperties(&encodingProperties));
        return winrt::Windows::Media::MediaProperties::VideoEncodingProperties{ encodingProperties, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::VideoStreamDescriptor) consume_Windows_Media_Core_IVideoStreamDescriptor2<D>::Copy() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IVideoStreamDescriptor2)->Copy(&result));
        return winrt::Windows::Media::Core::VideoStreamDescriptor{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::VideoStreamDescriptor) consume_Windows_Media_Core_IVideoStreamDescriptorFactory<D>::Create(winrt::Windows::Media::MediaProperties::VideoEncodingProperties const& encodingProperties) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IVideoStreamDescriptorFactory)->Create(*(void**)(&encodingProperties), &result));
        return winrt::Windows::Media::Core::VideoStreamDescriptor{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_IVideoTrack<D>::OpenFailed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::VideoTrack, winrt::Windows::Media::Core::VideoTrackOpenFailedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IVideoTrack)->add_OpenFailed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_IVideoTrack<D>::OpenFailed_revoker consume_Windows_Media_Core_IVideoTrack<D>::OpenFailed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::VideoTrack, winrt::Windows::Media::Core::VideoTrackOpenFailedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, OpenFailed_revoker>(this, OpenFailed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_IVideoTrack<D>::OpenFailed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IVideoTrack)->remove_OpenFailed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::VideoEncodingProperties) consume_Windows_Media_Core_IVideoTrack<D>::GetEncodingProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IVideoTrack)->GetEncodingProperties(&value));
        return winrt::Windows::Media::MediaProperties::VideoEncodingProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::MediaPlaybackItem) consume_Windows_Media_Core_IVideoTrack<D>::PlaybackItem() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IVideoTrack)->get_PlaybackItem(&value));
        return winrt::Windows::Media::Playback::MediaPlaybackItem{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Core_IVideoTrack<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IVideoTrack)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::VideoTrackSupportInfo) consume_Windows_Media_Core_IVideoTrack<D>::SupportInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IVideoTrack)->get_SupportInfo(&value));
        return winrt::Windows::Media::Core::VideoTrackSupportInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Media_Core_IVideoTrackOpenFailedEventArgs<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IVideoTrackOpenFailedEventArgs)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaDecoderStatus) consume_Windows_Media_Core_IVideoTrackSupportInfo<D>::DecoderStatus() const
    {
        winrt::Windows::Media::Core::MediaDecoderStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IVideoTrackSupportInfo)->get_DecoderStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaSourceStatus) consume_Windows_Media_Core_IVideoTrackSupportInfo<D>::MediaSourceStatus() const
    {
        winrt::Windows::Media::Core::MediaSourceStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::IVideoTrackSupportInfo)->get_MediaSourceStatus(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IAudioStreamDescriptor> : produce_base<D, winrt::Windows::Media::Core::IAudioStreamDescriptor>
    {
        int32_t __stdcall get_EncodingProperties(void** encodingProperties) noexcept final try
        {
            clear_abi(encodingProperties);
            typename D::abi_guard guard(this->shim());
            *encodingProperties = detach_from<winrt::Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().EncodingProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IAudioStreamDescriptor2> : produce_base<D, winrt::Windows::Media::Core::IAudioStreamDescriptor2>
    {
        int32_t __stdcall put_LeadingEncoderPadding(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LeadingEncoderPadding(*reinterpret_cast<winrt::Windows::Foundation::IReference<uint32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LeadingEncoderPadding(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().LeadingEncoderPadding());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TrailingEncoderPadding(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TrailingEncoderPadding(*reinterpret_cast<winrt::Windows::Foundation::IReference<uint32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TrailingEncoderPadding(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<uint32_t>>(this->shim().TrailingEncoderPadding());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IAudioStreamDescriptor3> : produce_base<D, winrt::Windows::Media::Core::IAudioStreamDescriptor3>
    {
        int32_t __stdcall Copy(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Core::AudioStreamDescriptor>(this->shim().Copy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IAudioStreamDescriptorFactory> : produce_base<D, winrt::Windows::Media::Core::IAudioStreamDescriptorFactory>
    {
        int32_t __stdcall Create(void* encodingProperties, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Core::AudioStreamDescriptor>(this->shim().Create(*reinterpret_cast<winrt::Windows::Media::MediaProperties::AudioEncodingProperties const*>(&encodingProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IAudioTrack> : produce_base<D, winrt::Windows::Media::Core::IAudioTrack>
    {
        int32_t __stdcall add_OpenFailed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().OpenFailed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::AudioTrack, winrt::Windows::Media::Core::AudioTrackOpenFailedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_OpenFailed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OpenFailed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall GetEncodingProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().GetEncodingProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PlaybackItem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackItem>(this->shim().PlaybackItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::AudioTrackSupportInfo>(this->shim().SupportInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IAudioTrackOpenFailedEventArgs> : produce_base<D, winrt::Windows::Media::Core::IAudioTrackOpenFailedEventArgs>
    {
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IAudioTrackSupportInfo> : produce_base<D, winrt::Windows::Media::Core::IAudioTrackSupportInfo>
    {
        int32_t __stdcall get_DecoderStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MediaDecoderStatus>(this->shim().DecoderStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Degradation(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::AudioDecoderDegradation>(this->shim().Degradation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DegradationReason(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::AudioDecoderDegradationReason>(this->shim().DegradationReason());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MediaSourceStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MediaSourceStatus>(this->shim().MediaSourceStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IChapterCue> : produce_base<D, winrt::Windows::Media::Core::IChapterCue>
    {
        int32_t __stdcall put_Title(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Title(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Title(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Title());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ICodecInfo> : produce_base<D, winrt::Windows::Media::Core::ICodecInfo>
    {
        int32_t __stdcall get_Kind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::CodecKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Category(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::CodecCategory>(this->shim().Category());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Subtypes(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().Subtypes());
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
        int32_t __stdcall get_IsTrusted(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsTrusted());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ICodecQuery> : produce_base<D, winrt::Windows::Media::Core::ICodecQuery>
    {
        int32_t __stdcall FindAllAsync(int32_t kind, int32_t category, void* subType, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Core::CodecInfo>>>(this->shim().FindAllAsync(*reinterpret_cast<winrt::Windows::Media::Core::CodecKind const*>(&kind), *reinterpret_cast<winrt::Windows::Media::Core::CodecCategory const*>(&category), *reinterpret_cast<hstring const*>(&subType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ICodecSubtypesStatics> : produce_base<D, winrt::Windows::Media::Core::ICodecSubtypesStatics>
    {
        int32_t __stdcall get_VideoFormatDV25(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoFormatDV25());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormatDV50(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoFormatDV50());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormatDvc(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoFormatDvc());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormatDvh1(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoFormatDvh1());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormatDvhD(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoFormatDvhD());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormatDvsd(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoFormatDvsd());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormatDvsl(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoFormatDvsl());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormatH263(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoFormatH263());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormatH264(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoFormatH264());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormatH265(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoFormatH265());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormatH264ES(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoFormatH264ES());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormatHevc(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoFormatHevc());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormatHevcES(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoFormatHevcES());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormatM4S2(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoFormatM4S2());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormatMjpg(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoFormatMjpg());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormatMP43(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoFormatMP43());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormatMP4S(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoFormatMP4S());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormatMP4V(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoFormatMP4V());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormatMpeg2(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoFormatMpeg2());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormatVP80(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoFormatVP80());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormatVP90(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoFormatVP90());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormatMpg1(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoFormatMpg1());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormatMss1(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoFormatMss1());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormatMss2(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoFormatMss2());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormatWmv1(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoFormatWmv1());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormatWmv2(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoFormatWmv2());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormatWmv3(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoFormatWmv3());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormatWvc1(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoFormatWvc1());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoFormat420O(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VideoFormat420O());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioFormatAac(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AudioFormatAac());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioFormatAdts(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AudioFormatAdts());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioFormatAlac(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AudioFormatAlac());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioFormatAmrNB(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AudioFormatAmrNB());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioFormatAmrWB(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AudioFormatAmrWB());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioFormatAmrWP(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AudioFormatAmrWP());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioFormatDolbyAC3(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AudioFormatDolbyAC3());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioFormatDolbyAC3Spdif(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AudioFormatDolbyAC3Spdif());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioFormatDolbyDDPlus(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AudioFormatDolbyDDPlus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioFormatDrm(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AudioFormatDrm());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioFormatDts(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AudioFormatDts());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioFormatFlac(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AudioFormatFlac());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioFormatFloat(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AudioFormatFloat());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioFormatMP3(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AudioFormatMP3());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioFormatMPeg(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AudioFormatMPeg());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioFormatMsp1(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AudioFormatMsp1());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioFormatOpus(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AudioFormatOpus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioFormatPcm(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AudioFormatPcm());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioFormatWmaSpdif(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AudioFormatWmaSpdif());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioFormatWMAudioLossless(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AudioFormatWMAudioLossless());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioFormatWMAudioV8(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AudioFormatWMAudioV8());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioFormatWMAudioV9(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AudioFormatWMAudioV9());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IDataCue> : produce_base<D, winrt::Windows::Media::Core::IDataCue>
    {
        int32_t __stdcall put_Data(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Data(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Data(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IBuffer>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IDataCue2> : produce_base<D, winrt::Windows::Media::Core::IDataCue2>
    {
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::PropertySet>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IFaceDetectedEventArgs> : produce_base<D, winrt::Windows::Media::Core::IFaceDetectedEventArgs>
    {
        int32_t __stdcall get_ResultFrame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::FaceDetectionEffectFrame>(this->shim().ResultFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IFaceDetectionEffect> : produce_base<D, winrt::Windows::Media::Core::IFaceDetectionEffect>
    {
        int32_t __stdcall put_Enabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Enabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Enabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Enabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DesiredDetectionInterval(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DesiredDetectionInterval(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DesiredDetectionInterval(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().DesiredDetectionInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_FaceDetected(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().FaceDetected(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::FaceDetectionEffect, winrt::Windows::Media::Core::FaceDetectedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_FaceDetected(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FaceDetected(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IFaceDetectionEffectDefinition> : produce_base<D, winrt::Windows::Media::Core::IFaceDetectionEffectDefinition>
    {
        int32_t __stdcall put_DetectionMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DetectionMode(*reinterpret_cast<winrt::Windows::Media::Core::FaceDetectionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DetectionMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::FaceDetectionMode>(this->shim().DetectionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SynchronousDetectionEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SynchronousDetectionEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SynchronousDetectionEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().SynchronousDetectionEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IFaceDetectionEffectFrame> : produce_base<D, winrt::Windows::Media::Core::IFaceDetectionEffectFrame>
    {
        int32_t __stdcall get_DetectedFaces(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::FaceAnalysis::DetectedFace>>(this->shim().DetectedFaces());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IHighDynamicRangeControl> : produce_base<D, winrt::Windows::Media::Core::IHighDynamicRangeControl>
    {
        int32_t __stdcall put_Enabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Enabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Enabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Enabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IHighDynamicRangeOutput> : produce_base<D, winrt::Windows::Media::Core::IHighDynamicRangeOutput>
    {
        int32_t __stdcall get_Certainty(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Certainty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FrameControllers(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Devices::Core::FrameController>>(this->shim().FrameControllers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IImageCue> : produce_base<D, winrt::Windows::Media::Core::IImageCue>
    {
        int32_t __stdcall get_Position(struct struct_Windows_Media_Core_TimedTextPoint* value) noexcept final try
        {
            zero_abi<winrt::Windows::Media::Core::TimedTextPoint>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextPoint>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Position(struct struct_Windows_Media_Core_TimedTextPoint value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Position(*reinterpret_cast<winrt::Windows::Media::Core::TimedTextPoint const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Extent(struct struct_Windows_Media_Core_TimedTextSize* value) noexcept final try
        {
            zero_abi<winrt::Windows::Media::Core::TimedTextSize>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextSize>(this->shim().Extent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Extent(struct struct_Windows_Media_Core_TimedTextSize value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Extent(*reinterpret_cast<winrt::Windows::Media::Core::TimedTextSize const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SoftwareBitmap(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SoftwareBitmap(*reinterpret_cast<winrt::Windows::Graphics::Imaging::SoftwareBitmap const*>(&value));
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
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IInitializeMediaStreamSourceRequestedEventArgs> : produce_base<D, winrt::Windows::Media::Core::IInitializeMediaStreamSourceRequestedEventArgs>
    {
        int32_t __stdcall get_Source(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MediaStreamSource>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RandomAccessStream(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStream>(this->shim().RandomAccessStream());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ILowLightFusionResult> : produce_base<D, winrt::Windows::Media::Core::ILowLightFusionResult>
    {
        int32_t __stdcall get_Frame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Imaging::SoftwareBitmap>(this->shim().Frame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ILowLightFusionStatics> : produce_base<D, winrt::Windows::Media::Core::ILowLightFusionStatics>
    {
        int32_t __stdcall get_SupportedBitmapPixelFormats(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Graphics::Imaging::BitmapPixelFormat>>(this->shim().SupportedBitmapPixelFormats());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxSupportedFrameCount(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MaxSupportedFrameCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FuseAsync(void* frameSet, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperationWithProgress<winrt::Windows::Media::Core::LowLightFusionResult, double>>(this->shim().FuseAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Graphics::Imaging::SoftwareBitmap> const*>(&frameSet)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaBinder> : produce_base<D, winrt::Windows::Media::Core::IMediaBinder>
    {
        int32_t __stdcall add_Binding(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Binding(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaBinder, winrt::Windows::Media::Core::MediaBindingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Binding(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Binding(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_Token(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Token());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Token(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Token(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Source(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MediaSource>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaBindingEventArgs> : produce_base<D, winrt::Windows::Media::Core::IMediaBindingEventArgs>
    {
        int32_t __stdcall add_Canceled(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Canceled(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaBindingEventArgs, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Canceled(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Canceled(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_MediaBinder(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MediaBinder>(this->shim().MediaBinder());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** deferral) noexcept final try
        {
            clear_abi(deferral);
            typename D::abi_guard guard(this->shim());
            *deferral = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetUri(void* uri) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStream(void* stream, void* contentType) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStream(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStream const*>(&stream), *reinterpret_cast<hstring const*>(&contentType));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStreamReference(void* stream, void* contentType) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStreamReference(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&stream), *reinterpret_cast<hstring const*>(&contentType));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaBindingEventArgs2> : produce_base<D, winrt::Windows::Media::Core::IMediaBindingEventArgs2>
    {
        int32_t __stdcall SetAdaptiveMediaSource(void* mediaSource) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetAdaptiveMediaSource(*reinterpret_cast<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSource const*>(&mediaSource));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetStorageFile(void* file) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetStorageFile(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaBindingEventArgs3> : produce_base<D, winrt::Windows::Media::Core::IMediaBindingEventArgs3>
    {
        int32_t __stdcall SetDownloadOperation(void* downloadOperation) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetDownloadOperation(*reinterpret_cast<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation const*>(&downloadOperation));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaCue> : produce_base<D, winrt::Windows::Media::Core::IMediaCue>
    {
        int32_t __stdcall put_StartTime(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartTime(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StartTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().StartTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Duration(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Duration(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
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
        int32_t __stdcall put_Id(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Id(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaCueEventArgs> : produce_base<D, winrt::Windows::Media::Core::IMediaCueEventArgs>
    {
        int32_t __stdcall get_Cue(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::IMediaCue>(this->shim().Cue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaSource> : produce_base<D, winrt::Windows::Media::Core::IMediaSource>
    {
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaSource2> : produce_base<D, winrt::Windows::Media::Core::IMediaSource2>
    {
        int32_t __stdcall add_OpenOperationCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().OpenOperationCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaSource, winrt::Windows::Media::Core::MediaSourceOpenOperationCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_OpenOperationCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OpenOperationCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_CustomProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::ValueSet>(this->shim().CustomProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Duration(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsOpen(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsOpen());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExternalTimedTextSources(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::Media::Core::TimedTextSource>>(this->shim().ExternalTimedTextSources());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExternalTimedMetadataTracks(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IObservableVector<winrt::Windows::Media::Core::TimedMetadataTrack>>(this->shim().ExternalTimedMetadataTracks());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaSource3> : produce_base<D, winrt::Windows::Media::Core::IMediaSource3>
    {
        int32_t __stdcall add_StateChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().StateChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaSource, winrt::Windows::Media::Core::MediaSourceStateChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StateChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_State(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MediaSourceState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Reset() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Reset();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaSource4> : produce_base<D, winrt::Windows::Media::Core::IMediaSource4>
    {
        int32_t __stdcall get_AdaptiveMediaSource(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSource>(this->shim().AdaptiveMediaSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MediaStreamSource(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MediaStreamSource>(this->shim().MediaStreamSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MseStreamSource(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MseStreamSource>(this->shim().MseStreamSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Uri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Uri>(this->shim().Uri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OpenAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().OpenAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaSource5> : produce_base<D, winrt::Windows::Media::Core::IMediaSource5>
    {
        int32_t __stdcall get_DownloadOperation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation>(this->shim().DownloadOperation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaSourceAppServiceConnection> : produce_base<D, winrt::Windows::Media::Core::IMediaSourceAppServiceConnection>
    {
        int32_t __stdcall add_InitializeMediaStreamSourceRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().InitializeMediaStreamSourceRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaSourceAppServiceConnection, winrt::Windows::Media::Core::InitializeMediaStreamSourceRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_InitializeMediaStreamSourceRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().InitializeMediaStreamSourceRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall Start() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaSourceAppServiceConnectionFactory> : produce_base<D, winrt::Windows::Media::Core::IMediaSourceAppServiceConnectionFactory>
    {
        int32_t __stdcall Create(void* appServiceConnection, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Core::MediaSourceAppServiceConnection>(this->shim().Create(*reinterpret_cast<winrt::Windows::ApplicationModel::AppService::AppServiceConnection const*>(&appServiceConnection)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaSourceError> : produce_base<D, winrt::Windows::Media::Core::IMediaSourceError>
    {
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaSourceOpenOperationCompletedEventArgs> : produce_base<D, winrt::Windows::Media::Core::IMediaSourceOpenOperationCompletedEventArgs>
    {
        int32_t __stdcall get_Error(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MediaSourceError>(this->shim().Error());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaSourceStateChangedEventArgs> : produce_base<D, winrt::Windows::Media::Core::IMediaSourceStateChangedEventArgs>
    {
        int32_t __stdcall get_OldState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MediaSourceState>(this->shim().OldState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NewState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MediaSourceState>(this->shim().NewState());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaSourceStatics> : produce_base<D, winrt::Windows::Media::Core::IMediaSourceStatics>
    {
        int32_t __stdcall CreateFromAdaptiveMediaSource(void* mediaSource, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Core::MediaSource>(this->shim().CreateFromAdaptiveMediaSource(*reinterpret_cast<winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSource const*>(&mediaSource)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromMediaStreamSource(void* mediaSource, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Core::MediaSource>(this->shim().CreateFromMediaStreamSource(*reinterpret_cast<winrt::Windows::Media::Core::MediaStreamSource const*>(&mediaSource)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromMseStreamSource(void* mediaSource, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Core::MediaSource>(this->shim().CreateFromMseStreamSource(*reinterpret_cast<winrt::Windows::Media::Core::MseStreamSource const*>(&mediaSource)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromIMediaSource(void* mediaSource, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Core::MediaSource>(this->shim().CreateFromIMediaSource(*reinterpret_cast<winrt::Windows::Media::Core::IMediaSource const*>(&mediaSource)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromStorageFile(void* file, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Core::MediaSource>(this->shim().CreateFromStorageFile(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromStream(void* stream, void* contentType, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Core::MediaSource>(this->shim().CreateFromStream(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStream const*>(&stream), *reinterpret_cast<hstring const*>(&contentType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromStreamReference(void* stream, void* contentType, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Core::MediaSource>(this->shim().CreateFromStreamReference(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&stream), *reinterpret_cast<hstring const*>(&contentType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromUri(void* uri, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Core::MediaSource>(this->shim().CreateFromUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaSourceStatics2> : produce_base<D, winrt::Windows::Media::Core::IMediaSourceStatics2>
    {
        int32_t __stdcall CreateFromMediaBinder(void* binder, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Core::MediaSource>(this->shim().CreateFromMediaBinder(*reinterpret_cast<winrt::Windows::Media::Core::MediaBinder const*>(&binder)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaSourceStatics3> : produce_base<D, winrt::Windows::Media::Core::IMediaSourceStatics3>
    {
        int32_t __stdcall CreateFromMediaFrameSource(void* frameSource, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Core::MediaSource>(this->shim().CreateFromMediaFrameSource(*reinterpret_cast<winrt::Windows::Media::Capture::Frames::MediaFrameSource const*>(&frameSource)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaSourceStatics4> : produce_base<D, winrt::Windows::Media::Core::IMediaSourceStatics4>
    {
        int32_t __stdcall CreateFromDownloadOperation(void* downloadOperation, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Core::MediaSource>(this->shim().CreateFromDownloadOperation(*reinterpret_cast<winrt::Windows::Networking::BackgroundTransfer::DownloadOperation const*>(&downloadOperation)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaStreamDescriptor> : produce_base<D, winrt::Windows::Media::Core::IMediaStreamDescriptor>
    {
        int32_t __stdcall get_IsSelected(bool* selected) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *selected = detach_from<bool>(this->shim().IsSelected());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Name(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Name(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Language(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Language(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Language(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Language());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaStreamDescriptor2> : produce_base<D, winrt::Windows::Media::Core::IMediaStreamDescriptor2>
    {
        int32_t __stdcall put_Label(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Label(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Label(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Label());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaStreamSample> : produce_base<D, winrt::Windows::Media::Core::IMediaStreamSample>
    {
        int32_t __stdcall add_Processed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Processed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaStreamSample, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Processed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Processed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_Buffer(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::Buffer>(this->shim().Buffer());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Timestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().Timestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MediaStreamSamplePropertySet>(this->shim().ExtendedProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Protection(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MediaStreamSampleProtectionProperties>(this->shim().Protection());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DecodeTimestamp(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DecodeTimestamp(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DecodeTimestamp(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().DecodeTimestamp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Duration(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Duration(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
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
        int32_t __stdcall put_KeyFrame(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().KeyFrame(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyFrame(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().KeyFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Discontinuous(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Discontinuous(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Discontinuous(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Discontinuous());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaStreamSample2> : produce_base<D, winrt::Windows::Media::Core::IMediaStreamSample2>
    {
        int32_t __stdcall get_Direct3D11Surface(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface>(this->shim().Direct3D11Surface());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaStreamSampleProtectionProperties> : produce_base<D, winrt::Windows::Media::Core::IMediaStreamSampleProtectionProperties>
    {
        int32_t __stdcall SetKeyIdentifier(uint32_t __valueSize, uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetKeyIdentifier(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(value), reinterpret_cast<uint8_t const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetKeyIdentifier(uint32_t* __valueSize, uint8_t** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            this->shim().GetKeyIdentifier(detach_abi<uint8_t>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetInitializationVector(uint32_t __valueSize, uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetInitializationVector(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(value), reinterpret_cast<uint8_t const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetInitializationVector(uint32_t* __valueSize, uint8_t** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            this->shim().GetInitializationVector(detach_abi<uint8_t>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetSubSampleMapping(uint32_t __valueSize, uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetSubSampleMapping(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(value), reinterpret_cast<uint8_t const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSubSampleMapping(uint32_t* __valueSize, uint8_t** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            this->shim().GetSubSampleMapping(detach_abi<uint8_t>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaStreamSampleStatics> : produce_base<D, winrt::Windows::Media::Core::IMediaStreamSampleStatics>
    {
        int32_t __stdcall CreateFromBuffer(void* buffer, int64_t timestamp, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MediaStreamSample>(this->shim().CreateFromBuffer(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&buffer), *reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&timestamp)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromStreamAsync(void* stream, uint32_t count, int64_t timestamp, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Core::MediaStreamSample>>(this->shim().CreateFromStreamAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IInputStream const*>(&stream), count, *reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&timestamp)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaStreamSampleStatics2> : produce_base<D, winrt::Windows::Media::Core::IMediaStreamSampleStatics2>
    {
        int32_t __stdcall CreateFromDirect3D11Surface(void* surface, int64_t timestamp, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Core::MediaStreamSample>(this->shim().CreateFromDirect3D11Surface(*reinterpret_cast<winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const*>(&surface), *reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&timestamp)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaStreamSource> : produce_base<D, winrt::Windows::Media::Core::IMediaStreamSource>
    {
        int32_t __stdcall add_Closed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaStreamSource, winrt::Windows::Media::Core::MediaStreamSourceClosedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Closed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Starting(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Starting(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaStreamSource, winrt::Windows::Media::Core::MediaStreamSourceStartingEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Starting(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Starting(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Paused(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Paused(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaStreamSource, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Paused(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Paused(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_SampleRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SampleRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaStreamSource, winrt::Windows::Media::Core::MediaStreamSourceSampleRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SampleRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SampleRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_SwitchStreamsRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SwitchStreamsRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaStreamSource, winrt::Windows::Media::Core::MediaStreamSourceSwitchStreamsRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SwitchStreamsRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SwitchStreamsRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall NotifyError(int32_t errorStatus) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NotifyError(*reinterpret_cast<winrt::Windows::Media::Core::MediaStreamSourceErrorStatus const*>(&errorStatus));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddStreamDescriptor(void* descriptor) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddStreamDescriptor(*reinterpret_cast<winrt::Windows::Media::Core::IMediaStreamDescriptor const*>(&descriptor));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MediaProtectionManager(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MediaProtectionManager(*reinterpret_cast<winrt::Windows::Media::Protection::MediaProtectionManager const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MediaProtectionManager(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Protection::MediaProtectionManager>(this->shim().MediaProtectionManager());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Duration(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Duration(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
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
        int32_t __stdcall put_CanSeek(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CanSeek(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CanSeek(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().CanSeek());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BufferTime(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BufferTime(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BufferTime(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().BufferTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetBufferedRange(int64_t startOffset, int64_t endOffset) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetBufferedRange(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&startOffset), *reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&endOffset));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MusicProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::FileProperties::MusicProperties>(this->shim().MusicProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VideoProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::FileProperties::VideoProperties>(this->shim().VideoProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Thumbnail(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Thumbnail(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStreamReference const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Thumbnail(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamReference>(this->shim().Thumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddProtectionKey(void* streamDescriptor, uint32_t __keyIdentifierSize, uint8_t* keyIdentifier, uint32_t __licenseDataSize, uint8_t* licenseData) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddProtectionKey(*reinterpret_cast<winrt::Windows::Media::Core::IMediaStreamDescriptor const*>(&streamDescriptor), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(keyIdentifier), reinterpret_cast<uint8_t const *>(keyIdentifier) + __keyIdentifierSize), array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(licenseData), reinterpret_cast<uint8_t const *>(licenseData) + __licenseDataSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaStreamSource2> : produce_base<D, winrt::Windows::Media::Core::IMediaStreamSource2>
    {
        int32_t __stdcall add_SampleRendered(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SampleRendered(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MediaStreamSource, winrt::Windows::Media::Core::MediaStreamSourceSampleRenderedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SampleRendered(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SampleRendered(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaStreamSource3> : produce_base<D, winrt::Windows::Media::Core::IMediaStreamSource3>
    {
        int32_t __stdcall put_MaxSupportedPlaybackRate(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxSupportedPlaybackRate(*reinterpret_cast<winrt::Windows::Foundation::IReference<double> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxSupportedPlaybackRate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<double>>(this->shim().MaxSupportedPlaybackRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaStreamSource4> : produce_base<D, winrt::Windows::Media::Core::IMediaStreamSource4>
    {
        int32_t __stdcall put_IsLive(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsLive(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsLive(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsLive());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaStreamSourceClosedEventArgs> : produce_base<D, winrt::Windows::Media::Core::IMediaStreamSourceClosedEventArgs>
    {
        int32_t __stdcall get_Request(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MediaStreamSourceClosedRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaStreamSourceClosedRequest> : produce_base<D, winrt::Windows::Media::Core::IMediaStreamSourceClosedRequest>
    {
        int32_t __stdcall get_Reason(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MediaStreamSourceClosedReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaStreamSourceFactory> : produce_base<D, winrt::Windows::Media::Core::IMediaStreamSourceFactory>
    {
        int32_t __stdcall CreateFromDescriptor(void* descriptor, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Core::MediaStreamSource>(this->shim().CreateFromDescriptor(*reinterpret_cast<winrt::Windows::Media::Core::IMediaStreamDescriptor const*>(&descriptor)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromDescriptors(void* descriptor, void* descriptor2, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Core::MediaStreamSource>(this->shim().CreateFromDescriptors(*reinterpret_cast<winrt::Windows::Media::Core::IMediaStreamDescriptor const*>(&descriptor), *reinterpret_cast<winrt::Windows::Media::Core::IMediaStreamDescriptor const*>(&descriptor2)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaStreamSourceSampleRenderedEventArgs> : produce_base<D, winrt::Windows::Media::Core::IMediaStreamSourceSampleRenderedEventArgs>
    {
        int32_t __stdcall get_SampleLag(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().SampleLag());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaStreamSourceSampleRequest> : produce_base<D, winrt::Windows::Media::Core::IMediaStreamSourceSampleRequest>
    {
        int32_t __stdcall get_StreamDescriptor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::IMediaStreamDescriptor>(this->shim().StreamDescriptor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** deferral) noexcept final try
        {
            clear_abi(deferral);
            typename D::abi_guard guard(this->shim());
            *deferral = detach_from<winrt::Windows::Media::Core::MediaStreamSourceSampleRequestDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Sample(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Sample(*reinterpret_cast<winrt::Windows::Media::Core::MediaStreamSample const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Sample(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MediaStreamSample>(this->shim().Sample());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportSampleProgress(uint32_t progress) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportSampleProgress(progress);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaStreamSourceSampleRequestDeferral> : produce_base<D, winrt::Windows::Media::Core::IMediaStreamSourceSampleRequestDeferral>
    {
        int32_t __stdcall Complete() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaStreamSourceSampleRequestedEventArgs> : produce_base<D, winrt::Windows::Media::Core::IMediaStreamSourceSampleRequestedEventArgs>
    {
        int32_t __stdcall get_Request(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MediaStreamSourceSampleRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaStreamSourceStartingEventArgs> : produce_base<D, winrt::Windows::Media::Core::IMediaStreamSourceStartingEventArgs>
    {
        int32_t __stdcall get_Request(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MediaStreamSourceStartingRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaStreamSourceStartingRequest> : produce_base<D, winrt::Windows::Media::Core::IMediaStreamSourceStartingRequest>
    {
        int32_t __stdcall get_StartPosition(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().StartPosition());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** deferral) noexcept final try
        {
            clear_abi(deferral);
            typename D::abi_guard guard(this->shim());
            *deferral = detach_from<winrt::Windows::Media::Core::MediaStreamSourceStartingRequestDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetActualStartPosition(int64_t position) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetActualStartPosition(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&position));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaStreamSourceStartingRequestDeferral> : produce_base<D, winrt::Windows::Media::Core::IMediaStreamSourceStartingRequestDeferral>
    {
        int32_t __stdcall Complete() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequest> : produce_base<D, winrt::Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequest>
    {
        int32_t __stdcall get_OldStreamDescriptor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::IMediaStreamDescriptor>(this->shim().OldStreamDescriptor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NewStreamDescriptor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::IMediaStreamDescriptor>(this->shim().NewStreamDescriptor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** deferral) noexcept final try
        {
            clear_abi(deferral);
            typename D::abi_guard guard(this->shim());
            *deferral = detach_from<winrt::Windows::Media::Core::MediaStreamSourceSwitchStreamsRequestDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequestDeferral> : produce_base<D, winrt::Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequestDeferral>
    {
        int32_t __stdcall Complete() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequestedEventArgs> : produce_base<D, winrt::Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequestedEventArgs>
    {
        int32_t __stdcall get_Request(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MediaStreamSourceSwitchStreamsRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMediaTrack> : produce_base<D, winrt::Windows::Media::Core::IMediaTrack>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Language(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Language());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TrackKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MediaTrackKind>(this->shim().TrackKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Label(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Label(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Label(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Label());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMseSourceBuffer> : produce_base<D, winrt::Windows::Media::Core::IMseSourceBuffer>
    {
        int32_t __stdcall add_UpdateStarting(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().UpdateStarting(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseSourceBuffer, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_UpdateStarting(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UpdateStarting(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Updated(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Updated(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseSourceBuffer, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Updated(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Updated(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_UpdateEnded(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().UpdateEnded(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseSourceBuffer, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_UpdateEnded(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UpdateEnded(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_ErrorOccurred(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ErrorOccurred(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseSourceBuffer, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ErrorOccurred(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ErrorOccurred(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Aborted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Aborted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseSourceBuffer, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Aborted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Aborted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_Mode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MseAppendMode>(this->shim().Mode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Mode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Mode(*reinterpret_cast<winrt::Windows::Media::Core::MseAppendMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsUpdating(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsUpdating());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Buffered(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Core::MseTimeRange>>(this->shim().Buffered());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TimestampOffset(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().TimestampOffset());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TimestampOffset(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TimestampOffset(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AppendWindowStart(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().AppendWindowStart());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AppendWindowStart(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AppendWindowStart(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AppendWindowEnd(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().AppendWindowEnd());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AppendWindowEnd(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AppendWindowEnd(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AppendBuffer(void* buffer) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AppendBuffer(*reinterpret_cast<winrt::Windows::Storage::Streams::IBuffer const*>(&buffer));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AppendStream(void* stream) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AppendStream(*reinterpret_cast<winrt::Windows::Storage::Streams::IInputStream const*>(&stream));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AppendStreamMaxSize(void* stream, uint64_t maxSize) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AppendStream(*reinterpret_cast<winrt::Windows::Storage::Streams::IInputStream const*>(&stream), maxSize);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Abort() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Abort();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Remove(int64_t start, void* end) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Remove(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&start), *reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const*>(&end));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMseSourceBufferList> : produce_base<D, winrt::Windows::Media::Core::IMseSourceBufferList>
    {
        int32_t __stdcall add_SourceBufferAdded(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SourceBufferAdded(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseSourceBufferList, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SourceBufferAdded(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SourceBufferAdded(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_SourceBufferRemoved(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SourceBufferRemoved(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseSourceBufferList, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SourceBufferRemoved(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SourceBufferRemoved(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_Buffers(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Core::MseSourceBuffer>>(this->shim().Buffers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMseStreamSource> : produce_base<D, winrt::Windows::Media::Core::IMseStreamSource>
    {
        int32_t __stdcall add_Opened(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Opened(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseStreamSource, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Opened(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Opened(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Ended(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Ended(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseStreamSource, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Ended(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Ended(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_Closed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Closed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::MseStreamSource, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Closed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Closed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_SourceBuffers(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MseSourceBufferList>(this->shim().SourceBuffers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ActiveSourceBuffers(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MseSourceBufferList>(this->shim().ActiveSourceBuffers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReadyState(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MseReadyState>(this->shim().ReadyState());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Duration(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().Duration());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Duration(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Duration(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddSourceBuffer(void* mimeType, void** buffer) noexcept final try
        {
            clear_abi(buffer);
            typename D::abi_guard guard(this->shim());
            *buffer = detach_from<winrt::Windows::Media::Core::MseSourceBuffer>(this->shim().AddSourceBuffer(*reinterpret_cast<hstring const*>(&mimeType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveSourceBuffer(void* buffer) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoveSourceBuffer(*reinterpret_cast<winrt::Windows::Media::Core::MseSourceBuffer const*>(&buffer));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall EndOfStream(int32_t status) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EndOfStream(*reinterpret_cast<winrt::Windows::Media::Core::MseEndOfStreamStatus const*>(&status));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMseStreamSource2> : produce_base<D, winrt::Windows::Media::Core::IMseStreamSource2>
    {
        int32_t __stdcall get_LiveSeekableRange(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Media::Core::MseTimeRange>>(this->shim().LiveSeekableRange());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LiveSeekableRange(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LiveSeekableRange(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Media::Core::MseTimeRange> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IMseStreamSourceStatics> : produce_base<D, winrt::Windows::Media::Core::IMseStreamSourceStatics>
    {
        int32_t __stdcall IsContentTypeSupported(void* contentType, bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsContentTypeSupported(*reinterpret_cast<hstring const*>(&contentType)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ISceneAnalysisEffect> : produce_base<D, winrt::Windows::Media::Core::ISceneAnalysisEffect>
    {
        int32_t __stdcall get_HighDynamicRangeAnalyzer(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::HighDynamicRangeControl>(this->shim().HighDynamicRangeAnalyzer());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DesiredAnalysisInterval(int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DesiredAnalysisInterval(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DesiredAnalysisInterval(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().DesiredAnalysisInterval());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_SceneAnalyzed(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().SceneAnalyzed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::SceneAnalysisEffect, winrt::Windows::Media::Core::SceneAnalyzedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SceneAnalyzed(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SceneAnalyzed(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ISceneAnalysisEffectFrame> : produce_base<D, winrt::Windows::Media::Core::ISceneAnalysisEffectFrame>
    {
        int32_t __stdcall get_FrameControlValues(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::CapturedFrameControlValues>(this->shim().FrameControlValues());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HighDynamicRange(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::HighDynamicRangeOutput>(this->shim().HighDynamicRange());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ISceneAnalysisEffectFrame2> : produce_base<D, winrt::Windows::Media::Core::ISceneAnalysisEffectFrame2>
    {
        int32_t __stdcall get_AnalysisRecommendation(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::SceneAnalysisRecommendation>(this->shim().AnalysisRecommendation());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ISceneAnalyzedEventArgs> : produce_base<D, winrt::Windows::Media::Core::ISceneAnalyzedEventArgs>
    {
        int32_t __stdcall get_ResultFrame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::SceneAnalysisEffectFrame>(this->shim().ResultFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ISingleSelectMediaTrackList> : produce_base<D, winrt::Windows::Media::Core::ISingleSelectMediaTrackList>
    {
        int32_t __stdcall add_SelectedIndexChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SelectedIndexChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::ISingleSelectMediaTrackList, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SelectedIndexChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectedIndexChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall put_SelectedIndex(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SelectedIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectedIndex(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().SelectedIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ISpeechCue> : produce_base<D, winrt::Windows::Media::Core::ISpeechCue>
    {
        int32_t __stdcall get_Text(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Text());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Text(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Text(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StartPositionInInput(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().StartPositionInInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StartPositionInInput(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartPositionInInput(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EndPositionInInput(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().EndPositionInInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EndPositionInInput(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EndPositionInInput(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ITimedMetadataStreamDescriptor> : produce_base<D, winrt::Windows::Media::Core::ITimedMetadataStreamDescriptor>
    {
        int32_t __stdcall get_EncodingProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::TimedMetadataEncodingProperties>(this->shim().EncodingProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Copy(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Core::TimedMetadataStreamDescriptor>(this->shim().Copy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ITimedMetadataStreamDescriptorFactory> : produce_base<D, winrt::Windows::Media::Core::ITimedMetadataStreamDescriptorFactory>
    {
        int32_t __stdcall Create(void* encodingProperties, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Core::TimedMetadataStreamDescriptor>(this->shim().Create(*reinterpret_cast<winrt::Windows::Media::MediaProperties::TimedMetadataEncodingProperties const*>(&encodingProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ITimedMetadataTrack> : produce_base<D, winrt::Windows::Media::Core::ITimedMetadataTrack>
    {
        int32_t __stdcall add_CueEntered(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CueEntered(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::TimedMetadataTrack, winrt::Windows::Media::Core::MediaCueEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CueEntered(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CueEntered(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_CueExited(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CueExited(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::TimedMetadataTrack, winrt::Windows::Media::Core::MediaCueEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CueExited(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CueExited(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_TrackFailed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().TrackFailed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::TimedMetadataTrack, winrt::Windows::Media::Core::TimedMetadataTrackFailedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_TrackFailed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TrackFailed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_Cues(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Core::IMediaCue>>(this->shim().Cues());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ActiveCues(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Core::IMediaCue>>(this->shim().ActiveCues());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TimedMetadataKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedMetadataKind>(this->shim().TimedMetadataKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DispatchType(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DispatchType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddCue(void* cue) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddCue(*reinterpret_cast<winrt::Windows::Media::Core::IMediaCue const*>(&cue));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveCue(void* cue) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoveCue(*reinterpret_cast<winrt::Windows::Media::Core::IMediaCue const*>(&cue));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ITimedMetadataTrack2> : produce_base<D, winrt::Windows::Media::Core::ITimedMetadataTrack2>
    {
        int32_t __stdcall get_PlaybackItem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackItem>(this->shim().PlaybackItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ITimedMetadataTrackError> : produce_base<D, winrt::Windows::Media::Core::ITimedMetadataTrackError>
    {
        int32_t __stdcall get_ErrorCode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedMetadataTrackErrorCode>(this->shim().ErrorCode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ITimedMetadataTrackFactory> : produce_base<D, winrt::Windows::Media::Core::ITimedMetadataTrackFactory>
    {
        int32_t __stdcall Create(void* id, void* language, int32_t kind, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedMetadataTrack>(this->shim().Create(*reinterpret_cast<hstring const*>(&id), *reinterpret_cast<hstring const*>(&language), *reinterpret_cast<winrt::Windows::Media::Core::TimedMetadataKind const*>(&kind)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ITimedMetadataTrackFailedEventArgs> : produce_base<D, winrt::Windows::Media::Core::ITimedMetadataTrackFailedEventArgs>
    {
        int32_t __stdcall get_Error(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedMetadataTrackError>(this->shim().Error());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ITimedMetadataTrackProvider> : produce_base<D, winrt::Windows::Media::Core::ITimedMetadataTrackProvider>
    {
        int32_t __stdcall get_TimedMetadataTracks(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Core::TimedMetadataTrack>>(this->shim().TimedMetadataTracks());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ITimedTextBouten> : produce_base<D, winrt::Windows::Media::Core::ITimedTextBouten>
    {
        int32_t __stdcall get_Type(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextBoutenType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Type(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Type(*reinterpret_cast<winrt::Windows::Media::Core::TimedTextBoutenType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Color(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().Color());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Color(struct struct_Windows_UI_Color value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Color(*reinterpret_cast<winrt::Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Position(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextBoutenPosition>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Position(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Position(*reinterpret_cast<winrt::Windows::Media::Core::TimedTextBoutenPosition const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ITimedTextCue> : produce_base<D, winrt::Windows::Media::Core::ITimedTextCue>
    {
        int32_t __stdcall get_CueRegion(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextRegion>(this->shim().CueRegion());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CueRegion(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CueRegion(*reinterpret_cast<winrt::Windows::Media::Core::TimedTextRegion const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CueStyle(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextStyle>(this->shim().CueStyle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CueStyle(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CueStyle(*reinterpret_cast<winrt::Windows::Media::Core::TimedTextStyle const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Lines(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Media::Core::TimedTextLine>>(this->shim().Lines());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ITimedTextLine> : produce_base<D, winrt::Windows::Media::Core::ITimedTextLine>
    {
        int32_t __stdcall get_Text(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Text());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Text(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Text(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Subformats(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Media::Core::TimedTextSubformat>>(this->shim().Subformats());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ITimedTextRegion> : produce_base<D, winrt::Windows::Media::Core::ITimedTextRegion>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Name(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Name(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Position(struct struct_Windows_Media_Core_TimedTextPoint* value) noexcept final try
        {
            zero_abi<winrt::Windows::Media::Core::TimedTextPoint>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextPoint>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Position(struct struct_Windows_Media_Core_TimedTextPoint value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Position(*reinterpret_cast<winrt::Windows::Media::Core::TimedTextPoint const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Extent(struct struct_Windows_Media_Core_TimedTextSize* value) noexcept final try
        {
            zero_abi<winrt::Windows::Media::Core::TimedTextSize>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextSize>(this->shim().Extent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Extent(struct struct_Windows_Media_Core_TimedTextSize value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Extent(*reinterpret_cast<winrt::Windows::Media::Core::TimedTextSize const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Background(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().Background());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Background(struct struct_Windows_UI_Color value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Background(*reinterpret_cast<winrt::Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WritingMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextWritingMode>(this->shim().WritingMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_WritingMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WritingMode(*reinterpret_cast<winrt::Windows::Media::Core::TimedTextWritingMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayAlignment(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextDisplayAlignment>(this->shim().DisplayAlignment());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DisplayAlignment(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisplayAlignment(*reinterpret_cast<winrt::Windows::Media::Core::TimedTextDisplayAlignment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LineHeight(struct struct_Windows_Media_Core_TimedTextDouble* value) noexcept final try
        {
            zero_abi<winrt::Windows::Media::Core::TimedTextDouble>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextDouble>(this->shim().LineHeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LineHeight(struct struct_Windows_Media_Core_TimedTextDouble value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LineHeight(*reinterpret_cast<winrt::Windows::Media::Core::TimedTextDouble const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsOverflowClipped(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsOverflowClipped());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsOverflowClipped(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsOverflowClipped(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Padding(struct struct_Windows_Media_Core_TimedTextPadding* value) noexcept final try
        {
            zero_abi<winrt::Windows::Media::Core::TimedTextPadding>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextPadding>(this->shim().Padding());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Padding(struct struct_Windows_Media_Core_TimedTextPadding value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Padding(*reinterpret_cast<winrt::Windows::Media::Core::TimedTextPadding const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TextWrapping(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextWrapping>(this->shim().TextWrapping());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_TextWrapping(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().TextWrapping(*reinterpret_cast<winrt::Windows::Media::Core::TimedTextWrapping const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ZIndex(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().ZIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ZIndex(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ZIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ScrollMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextScrollMode>(this->shim().ScrollMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ScrollMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ScrollMode(*reinterpret_cast<winrt::Windows::Media::Core::TimedTextScrollMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ITimedTextRuby> : produce_base<D, winrt::Windows::Media::Core::ITimedTextRuby>
    {
        int32_t __stdcall get_Text(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Text());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Text(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Text(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Position(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextRubyPosition>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Position(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Position(*reinterpret_cast<winrt::Windows::Media::Core::TimedTextRubyPosition const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Align(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextRubyAlign>(this->shim().Align());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Align(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Align(*reinterpret_cast<winrt::Windows::Media::Core::TimedTextRubyAlign const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Reserve(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextRubyReserve>(this->shim().Reserve());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Reserve(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Reserve(*reinterpret_cast<winrt::Windows::Media::Core::TimedTextRubyReserve const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ITimedTextSource> : produce_base<D, winrt::Windows::Media::Core::ITimedTextSource>
    {
        int32_t __stdcall add_Resolved(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().Resolved(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::TimedTextSource, winrt::Windows::Media::Core::TimedTextSourceResolveResultEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_Resolved(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Resolved(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ITimedTextSourceResolveResultEventArgs> : produce_base<D, winrt::Windows::Media::Core::ITimedTextSourceResolveResultEventArgs>
    {
        int32_t __stdcall get_Error(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedMetadataTrackError>(this->shim().Error());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Tracks(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Core::TimedMetadataTrack>>(this->shim().Tracks());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ITimedTextSourceStatics> : produce_base<D, winrt::Windows::Media::Core::ITimedTextSourceStatics>
    {
        int32_t __stdcall CreateFromStream(void* stream, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextSource>(this->shim().CreateFromStream(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStream const*>(&stream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromUri(void* uri, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextSource>(this->shim().CreateFromUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromStreamWithLanguage(void* stream, void* defaultLanguage, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextSource>(this->shim().CreateFromStream(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStream const*>(&stream), *reinterpret_cast<hstring const*>(&defaultLanguage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromUriWithLanguage(void* uri, void* defaultLanguage, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextSource>(this->shim().CreateFromUri(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<hstring const*>(&defaultLanguage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ITimedTextSourceStatics2> : produce_base<D, winrt::Windows::Media::Core::ITimedTextSourceStatics2>
    {
        int32_t __stdcall CreateFromStreamWithIndex(void* stream, void* indexStream, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Core::TimedTextSource>(this->shim().CreateFromStreamWithIndex(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStream const*>(&stream), *reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStream const*>(&indexStream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromUriWithIndex(void* uri, void* indexUri, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Core::TimedTextSource>(this->shim().CreateFromUriWithIndex(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&indexUri)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromStreamWithIndexAndLanguage(void* stream, void* indexStream, void* defaultLanguage, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Core::TimedTextSource>(this->shim().CreateFromStreamWithIndex(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStream const*>(&stream), *reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStream const*>(&indexStream), *reinterpret_cast<hstring const*>(&defaultLanguage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromUriWithIndexAndLanguage(void* uri, void* indexUri, void* defaultLanguage, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Core::TimedTextSource>(this->shim().CreateFromUriWithIndex(*reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&uri), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&indexUri), *reinterpret_cast<hstring const*>(&defaultLanguage)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ITimedTextStyle> : produce_base<D, winrt::Windows::Media::Core::ITimedTextStyle>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Name(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Name(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FontFamily(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FontFamily());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FontFamily(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FontFamily(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FontSize(struct struct_Windows_Media_Core_TimedTextDouble* value) noexcept final try
        {
            zero_abi<winrt::Windows::Media::Core::TimedTextDouble>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextDouble>(this->shim().FontSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FontSize(struct struct_Windows_Media_Core_TimedTextDouble value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FontSize(*reinterpret_cast<winrt::Windows::Media::Core::TimedTextDouble const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FontWeight(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextWeight>(this->shim().FontWeight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FontWeight(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FontWeight(*reinterpret_cast<winrt::Windows::Media::Core::TimedTextWeight const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Foreground(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().Foreground());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Foreground(struct struct_Windows_UI_Color value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Foreground(*reinterpret_cast<winrt::Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Background(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().Background());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Background(struct struct_Windows_UI_Color value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Background(*reinterpret_cast<winrt::Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsBackgroundAlwaysShown(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsBackgroundAlwaysShown());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsBackgroundAlwaysShown(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsBackgroundAlwaysShown(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FlowDirection(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextFlowDirection>(this->shim().FlowDirection());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FlowDirection(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FlowDirection(*reinterpret_cast<winrt::Windows::Media::Core::TimedTextFlowDirection const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LineAlignment(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextLineAlignment>(this->shim().LineAlignment());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LineAlignment(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LineAlignment(*reinterpret_cast<winrt::Windows::Media::Core::TimedTextLineAlignment const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OutlineColor(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().OutlineColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OutlineColor(struct struct_Windows_UI_Color value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OutlineColor(*reinterpret_cast<winrt::Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OutlineThickness(struct struct_Windows_Media_Core_TimedTextDouble* value) noexcept final try
        {
            zero_abi<winrt::Windows::Media::Core::TimedTextDouble>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextDouble>(this->shim().OutlineThickness());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OutlineThickness(struct struct_Windows_Media_Core_TimedTextDouble value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OutlineThickness(*reinterpret_cast<winrt::Windows::Media::Core::TimedTextDouble const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OutlineRadius(struct struct_Windows_Media_Core_TimedTextDouble* value) noexcept final try
        {
            zero_abi<winrt::Windows::Media::Core::TimedTextDouble>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextDouble>(this->shim().OutlineRadius());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OutlineRadius(struct struct_Windows_Media_Core_TimedTextDouble value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OutlineRadius(*reinterpret_cast<winrt::Windows::Media::Core::TimedTextDouble const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ITimedTextStyle2> : produce_base<D, winrt::Windows::Media::Core::ITimedTextStyle2>
    {
        int32_t __stdcall get_FontStyle(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextFontStyle>(this->shim().FontStyle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FontStyle(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FontStyle(*reinterpret_cast<winrt::Windows::Media::Core::TimedTextFontStyle const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsUnderlineEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsUnderlineEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsUnderlineEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsUnderlineEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsLineThroughEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsLineThroughEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsLineThroughEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsLineThroughEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsOverlineEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsOverlineEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsOverlineEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsOverlineEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ITimedTextStyle3> : produce_base<D, winrt::Windows::Media::Core::ITimedTextStyle3>
    {
        int32_t __stdcall get_Ruby(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextRuby>(this->shim().Ruby());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Bouten(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextBouten>(this->shim().Bouten());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsTextCombined(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsTextCombined());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsTextCombined(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsTextCombined(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FontAngleInDegrees(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().FontAngleInDegrees());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FontAngleInDegrees(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FontAngleInDegrees(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::ITimedTextSubformat> : produce_base<D, winrt::Windows::Media::Core::ITimedTextSubformat>
    {
        int32_t __stdcall get_StartIndex(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().StartIndex());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StartIndex(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartIndex(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Length(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Length());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Length(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Length(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SubformatStyle(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::TimedTextStyle>(this->shim().SubformatStyle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SubformatStyle(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SubformatStyle(*reinterpret_cast<winrt::Windows::Media::Core::TimedTextStyle const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IVideoStabilizationEffect> : produce_base<D, winrt::Windows::Media::Core::IVideoStabilizationEffect>
    {
        int32_t __stdcall put_Enabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Enabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Enabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Enabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_EnabledChanged(void* handler, winrt::event_token* cookie) noexcept final try
        {
            zero_abi<winrt::event_token>(cookie);
            typename D::abi_guard guard(this->shim());
            *cookie = detach_from<winrt::event_token>(this->shim().EnabledChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::VideoStabilizationEffect, winrt::Windows::Media::Core::VideoStabilizationEffectEnabledChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_EnabledChanged(winrt::event_token cookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnabledChanged(*reinterpret_cast<winrt::event_token const*>(&cookie));
            return 0;
        }
        int32_t __stdcall GetRecommendedStreamConfiguration(void* controller, void* desiredProperties, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Capture::VideoStreamConfiguration>(this->shim().GetRecommendedStreamConfiguration(*reinterpret_cast<winrt::Windows::Media::Devices::VideoDeviceController const*>(&controller), *reinterpret_cast<winrt::Windows::Media::MediaProperties::VideoEncodingProperties const*>(&desiredProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IVideoStabilizationEffectEnabledChangedEventArgs> : produce_base<D, winrt::Windows::Media::Core::IVideoStabilizationEffectEnabledChangedEventArgs>
    {
        int32_t __stdcall get_Reason(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::VideoStabilizationEffectEnabledChangedReason>(this->shim().Reason());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IVideoStreamDescriptor> : produce_base<D, winrt::Windows::Media::Core::IVideoStreamDescriptor>
    {
        int32_t __stdcall get_EncodingProperties(void** encodingProperties) noexcept final try
        {
            clear_abi(encodingProperties);
            typename D::abi_guard guard(this->shim());
            *encodingProperties = detach_from<winrt::Windows::Media::MediaProperties::VideoEncodingProperties>(this->shim().EncodingProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IVideoStreamDescriptor2> : produce_base<D, winrt::Windows::Media::Core::IVideoStreamDescriptor2>
    {
        int32_t __stdcall Copy(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Core::VideoStreamDescriptor>(this->shim().Copy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IVideoStreamDescriptorFactory> : produce_base<D, winrt::Windows::Media::Core::IVideoStreamDescriptorFactory>
    {
        int32_t __stdcall Create(void* encodingProperties, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Core::VideoStreamDescriptor>(this->shim().Create(*reinterpret_cast<winrt::Windows::Media::MediaProperties::VideoEncodingProperties const*>(&encodingProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IVideoTrack> : produce_base<D, winrt::Windows::Media::Core::IVideoTrack>
    {
        int32_t __stdcall add_OpenFailed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().OpenFailed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Core::VideoTrack, winrt::Windows::Media::Core::VideoTrackOpenFailedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_OpenFailed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OpenFailed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall GetEncodingProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::VideoEncodingProperties>(this->shim().GetEncodingProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PlaybackItem(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::MediaPlaybackItem>(this->shim().PlaybackItem());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::VideoTrackSupportInfo>(this->shim().SupportInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IVideoTrackOpenFailedEventArgs> : produce_base<D, winrt::Windows::Media::Core::IVideoTrackOpenFailedEventArgs>
    {
        int32_t __stdcall get_ExtendedError(winrt::hresult* value) noexcept final try
        {
            zero_abi<winrt::hresult>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::hresult>(this->shim().ExtendedError());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::IVideoTrackSupportInfo> : produce_base<D, winrt::Windows::Media::Core::IVideoTrackSupportInfo>
    {
        int32_t __stdcall get_DecoderStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MediaDecoderStatus>(this->shim().DecoderStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MediaSourceStatus(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MediaSourceStatus>(this->shim().MediaSourceStatus());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Media::Core
{
    inline AudioStreamDescriptor::AudioStreamDescriptor(winrt::Windows::Media::MediaProperties::AudioEncodingProperties const& encodingProperties) :
        AudioStreamDescriptor(impl::call_factory<AudioStreamDescriptor, IAudioStreamDescriptorFactory>([&](IAudioStreamDescriptorFactory const& f) { return f.Create(encodingProperties); }))
    {
    }
    inline ChapterCue::ChapterCue() :
        ChapterCue(impl::call_factory_cast<ChapterCue(*)(winrt::Windows::Foundation::IActivationFactory const&), ChapterCue>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ChapterCue>(); }))
    {
    }
    inline CodecQuery::CodecQuery() :
        CodecQuery(impl::call_factory_cast<CodecQuery(*)(winrt::Windows::Foundation::IActivationFactory const&), CodecQuery>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<CodecQuery>(); }))
    {
    }
    inline auto CodecSubtypes::VideoFormatDV25()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.VideoFormatDV25(); });
    }
    inline auto CodecSubtypes::VideoFormatDV50()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.VideoFormatDV50(); });
    }
    inline auto CodecSubtypes::VideoFormatDvc()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.VideoFormatDvc(); });
    }
    inline auto CodecSubtypes::VideoFormatDvh1()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.VideoFormatDvh1(); });
    }
    inline auto CodecSubtypes::VideoFormatDvhD()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.VideoFormatDvhD(); });
    }
    inline auto CodecSubtypes::VideoFormatDvsd()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.VideoFormatDvsd(); });
    }
    inline auto CodecSubtypes::VideoFormatDvsl()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.VideoFormatDvsl(); });
    }
    inline auto CodecSubtypes::VideoFormatH263()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.VideoFormatH263(); });
    }
    inline auto CodecSubtypes::VideoFormatH264()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.VideoFormatH264(); });
    }
    inline auto CodecSubtypes::VideoFormatH265()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.VideoFormatH265(); });
    }
    inline auto CodecSubtypes::VideoFormatH264ES()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.VideoFormatH264ES(); });
    }
    inline auto CodecSubtypes::VideoFormatHevc()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.VideoFormatHevc(); });
    }
    inline auto CodecSubtypes::VideoFormatHevcES()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.VideoFormatHevcES(); });
    }
    inline auto CodecSubtypes::VideoFormatM4S2()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.VideoFormatM4S2(); });
    }
    inline auto CodecSubtypes::VideoFormatMjpg()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.VideoFormatMjpg(); });
    }
    inline auto CodecSubtypes::VideoFormatMP43()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.VideoFormatMP43(); });
    }
    inline auto CodecSubtypes::VideoFormatMP4S()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.VideoFormatMP4S(); });
    }
    inline auto CodecSubtypes::VideoFormatMP4V()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.VideoFormatMP4V(); });
    }
    inline auto CodecSubtypes::VideoFormatMpeg2()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.VideoFormatMpeg2(); });
    }
    inline auto CodecSubtypes::VideoFormatVP80()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.VideoFormatVP80(); });
    }
    inline auto CodecSubtypes::VideoFormatVP90()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.VideoFormatVP90(); });
    }
    inline auto CodecSubtypes::VideoFormatMpg1()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.VideoFormatMpg1(); });
    }
    inline auto CodecSubtypes::VideoFormatMss1()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.VideoFormatMss1(); });
    }
    inline auto CodecSubtypes::VideoFormatMss2()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.VideoFormatMss2(); });
    }
    inline auto CodecSubtypes::VideoFormatWmv1()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.VideoFormatWmv1(); });
    }
    inline auto CodecSubtypes::VideoFormatWmv2()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.VideoFormatWmv2(); });
    }
    inline auto CodecSubtypes::VideoFormatWmv3()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.VideoFormatWmv3(); });
    }
    inline auto CodecSubtypes::VideoFormatWvc1()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.VideoFormatWvc1(); });
    }
    inline auto CodecSubtypes::VideoFormat420O()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.VideoFormat420O(); });
    }
    inline auto CodecSubtypes::AudioFormatAac()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.AudioFormatAac(); });
    }
    inline auto CodecSubtypes::AudioFormatAdts()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.AudioFormatAdts(); });
    }
    inline auto CodecSubtypes::AudioFormatAlac()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.AudioFormatAlac(); });
    }
    inline auto CodecSubtypes::AudioFormatAmrNB()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.AudioFormatAmrNB(); });
    }
    inline auto CodecSubtypes::AudioFormatAmrWB()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.AudioFormatAmrWB(); });
    }
    inline auto CodecSubtypes::AudioFormatAmrWP()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.AudioFormatAmrWP(); });
    }
    inline auto CodecSubtypes::AudioFormatDolbyAC3()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.AudioFormatDolbyAC3(); });
    }
    inline auto CodecSubtypes::AudioFormatDolbyAC3Spdif()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.AudioFormatDolbyAC3Spdif(); });
    }
    inline auto CodecSubtypes::AudioFormatDolbyDDPlus()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.AudioFormatDolbyDDPlus(); });
    }
    inline auto CodecSubtypes::AudioFormatDrm()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.AudioFormatDrm(); });
    }
    inline auto CodecSubtypes::AudioFormatDts()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.AudioFormatDts(); });
    }
    inline auto CodecSubtypes::AudioFormatFlac()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.AudioFormatFlac(); });
    }
    inline auto CodecSubtypes::AudioFormatFloat()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.AudioFormatFloat(); });
    }
    inline auto CodecSubtypes::AudioFormatMP3()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.AudioFormatMP3(); });
    }
    inline auto CodecSubtypes::AudioFormatMPeg()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.AudioFormatMPeg(); });
    }
    inline auto CodecSubtypes::AudioFormatMsp1()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.AudioFormatMsp1(); });
    }
    inline auto CodecSubtypes::AudioFormatOpus()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.AudioFormatOpus(); });
    }
    inline auto CodecSubtypes::AudioFormatPcm()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.AudioFormatPcm(); });
    }
    inline auto CodecSubtypes::AudioFormatWmaSpdif()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.AudioFormatWmaSpdif(); });
    }
    inline auto CodecSubtypes::AudioFormatWMAudioLossless()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.AudioFormatWMAudioLossless(); });
    }
    inline auto CodecSubtypes::AudioFormatWMAudioV8()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.AudioFormatWMAudioV8(); });
    }
    inline auto CodecSubtypes::AudioFormatWMAudioV9()
    {
        return impl::call_factory_cast<hstring(*)(ICodecSubtypesStatics const&), CodecSubtypes, ICodecSubtypesStatics>([](ICodecSubtypesStatics const& f) { return f.AudioFormatWMAudioV9(); });
    }
    inline DataCue::DataCue() :
        DataCue(impl::call_factory_cast<DataCue(*)(winrt::Windows::Foundation::IActivationFactory const&), DataCue>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<DataCue>(); }))
    {
    }
    inline FaceDetectionEffectDefinition::FaceDetectionEffectDefinition() :
        FaceDetectionEffectDefinition(impl::call_factory_cast<FaceDetectionEffectDefinition(*)(winrt::Windows::Foundation::IActivationFactory const&), FaceDetectionEffectDefinition>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<FaceDetectionEffectDefinition>(); }))
    {
    }
    inline ImageCue::ImageCue() :
        ImageCue(impl::call_factory_cast<ImageCue(*)(winrt::Windows::Foundation::IActivationFactory const&), ImageCue>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ImageCue>(); }))
    {
    }
    inline auto LowLightFusion::SupportedBitmapPixelFormats()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Graphics::Imaging::BitmapPixelFormat>(*)(ILowLightFusionStatics const&), LowLightFusion, ILowLightFusionStatics>([](ILowLightFusionStatics const& f) { return f.SupportedBitmapPixelFormats(); });
    }
    inline auto LowLightFusion::MaxSupportedFrameCount()
    {
        return impl::call_factory_cast<int32_t(*)(ILowLightFusionStatics const&), LowLightFusion, ILowLightFusionStatics>([](ILowLightFusionStatics const& f) { return f.MaxSupportedFrameCount(); });
    }
    inline auto LowLightFusion::FuseAsync(param::async_iterable<winrt::Windows::Graphics::Imaging::SoftwareBitmap> const& frameSet)
    {
        return impl::call_factory<LowLightFusion, ILowLightFusionStatics>([&](ILowLightFusionStatics const& f) { return f.FuseAsync(frameSet); });
    }
    inline MediaBinder::MediaBinder() :
        MediaBinder(impl::call_factory_cast<MediaBinder(*)(winrt::Windows::Foundation::IActivationFactory const&), MediaBinder>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<MediaBinder>(); }))
    {
    }
    inline auto MediaSource::CreateFromAdaptiveMediaSource(winrt::Windows::Media::Streaming::Adaptive::AdaptiveMediaSource const& mediaSource)
    {
        return impl::call_factory<MediaSource, IMediaSourceStatics>([&](IMediaSourceStatics const& f) { return f.CreateFromAdaptiveMediaSource(mediaSource); });
    }
    inline auto MediaSource::CreateFromMediaStreamSource(winrt::Windows::Media::Core::MediaStreamSource const& mediaSource)
    {
        return impl::call_factory<MediaSource, IMediaSourceStatics>([&](IMediaSourceStatics const& f) { return f.CreateFromMediaStreamSource(mediaSource); });
    }
    inline auto MediaSource::CreateFromMseStreamSource(winrt::Windows::Media::Core::MseStreamSource const& mediaSource)
    {
        return impl::call_factory<MediaSource, IMediaSourceStatics>([&](IMediaSourceStatics const& f) { return f.CreateFromMseStreamSource(mediaSource); });
    }
    inline auto MediaSource::CreateFromIMediaSource(winrt::Windows::Media::Core::IMediaSource const& mediaSource)
    {
        return impl::call_factory<MediaSource, IMediaSourceStatics>([&](IMediaSourceStatics const& f) { return f.CreateFromIMediaSource(mediaSource); });
    }
    inline auto MediaSource::CreateFromStorageFile(winrt::Windows::Storage::IStorageFile const& file)
    {
        return impl::call_factory<MediaSource, IMediaSourceStatics>([&](IMediaSourceStatics const& f) { return f.CreateFromStorageFile(file); });
    }
    inline auto MediaSource::CreateFromStream(winrt::Windows::Storage::Streams::IRandomAccessStream const& stream, param::hstring const& contentType)
    {
        return impl::call_factory<MediaSource, IMediaSourceStatics>([&](IMediaSourceStatics const& f) { return f.CreateFromStream(stream, contentType); });
    }
    inline auto MediaSource::CreateFromStreamReference(winrt::Windows::Storage::Streams::IRandomAccessStreamReference const& stream, param::hstring const& contentType)
    {
        return impl::call_factory<MediaSource, IMediaSourceStatics>([&](IMediaSourceStatics const& f) { return f.CreateFromStreamReference(stream, contentType); });
    }
    inline auto MediaSource::CreateFromUri(winrt::Windows::Foundation::Uri const& uri)
    {
        return impl::call_factory<MediaSource, IMediaSourceStatics>([&](IMediaSourceStatics const& f) { return f.CreateFromUri(uri); });
    }
    inline auto MediaSource::CreateFromMediaBinder(winrt::Windows::Media::Core::MediaBinder const& binder)
    {
        return impl::call_factory<MediaSource, IMediaSourceStatics2>([&](IMediaSourceStatics2 const& f) { return f.CreateFromMediaBinder(binder); });
    }
    inline auto MediaSource::CreateFromMediaFrameSource(winrt::Windows::Media::Capture::Frames::MediaFrameSource const& frameSource)
    {
        return impl::call_factory<MediaSource, IMediaSourceStatics3>([&](IMediaSourceStatics3 const& f) { return f.CreateFromMediaFrameSource(frameSource); });
    }
    inline auto MediaSource::CreateFromDownloadOperation(winrt::Windows::Networking::BackgroundTransfer::DownloadOperation const& downloadOperation)
    {
        return impl::call_factory<MediaSource, IMediaSourceStatics4>([&](IMediaSourceStatics4 const& f) { return f.CreateFromDownloadOperation(downloadOperation); });
    }
    inline MediaSourceAppServiceConnection::MediaSourceAppServiceConnection(winrt::Windows::ApplicationModel::AppService::AppServiceConnection const& appServiceConnection) :
        MediaSourceAppServiceConnection(impl::call_factory<MediaSourceAppServiceConnection, IMediaSourceAppServiceConnectionFactory>([&](IMediaSourceAppServiceConnectionFactory const& f) { return f.Create(appServiceConnection); }))
    {
    }
    inline auto MediaStreamSample::CreateFromBuffer(winrt::Windows::Storage::Streams::IBuffer const& buffer, winrt::Windows::Foundation::TimeSpan const& timestamp)
    {
        return impl::call_factory<MediaStreamSample, IMediaStreamSampleStatics>([&](IMediaStreamSampleStatics const& f) { return f.CreateFromBuffer(buffer, timestamp); });
    }
    inline auto MediaStreamSample::CreateFromStreamAsync(winrt::Windows::Storage::Streams::IInputStream const& stream, uint32_t count, winrt::Windows::Foundation::TimeSpan const& timestamp)
    {
        return impl::call_factory<MediaStreamSample, IMediaStreamSampleStatics>([&](IMediaStreamSampleStatics const& f) { return f.CreateFromStreamAsync(stream, count, timestamp); });
    }
    inline auto MediaStreamSample::CreateFromDirect3D11Surface(winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& surface, winrt::Windows::Foundation::TimeSpan const& timestamp)
    {
        return impl::call_factory<MediaStreamSample, IMediaStreamSampleStatics2>([&](IMediaStreamSampleStatics2 const& f) { return f.CreateFromDirect3D11Surface(surface, timestamp); });
    }
    inline MediaStreamSource::MediaStreamSource(winrt::Windows::Media::Core::IMediaStreamDescriptor const& descriptor) :
        MediaStreamSource(impl::call_factory<MediaStreamSource, IMediaStreamSourceFactory>([&](IMediaStreamSourceFactory const& f) { return f.CreateFromDescriptor(descriptor); }))
    {
    }
    inline MediaStreamSource::MediaStreamSource(winrt::Windows::Media::Core::IMediaStreamDescriptor const& descriptor, winrt::Windows::Media::Core::IMediaStreamDescriptor const& descriptor2) :
        MediaStreamSource(impl::call_factory<MediaStreamSource, IMediaStreamSourceFactory>([&](IMediaStreamSourceFactory const& f) { return f.CreateFromDescriptors(descriptor, descriptor2); }))
    {
    }
    inline MseStreamSource::MseStreamSource() :
        MseStreamSource(impl::call_factory_cast<MseStreamSource(*)(winrt::Windows::Foundation::IActivationFactory const&), MseStreamSource>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<MseStreamSource>(); }))
    {
    }
    inline auto MseStreamSource::IsContentTypeSupported(param::hstring const& contentType)
    {
        return impl::call_factory<MseStreamSource, IMseStreamSourceStatics>([&](IMseStreamSourceStatics const& f) { return f.IsContentTypeSupported(contentType); });
    }
    inline SceneAnalysisEffectDefinition::SceneAnalysisEffectDefinition() :
        SceneAnalysisEffectDefinition(impl::call_factory_cast<SceneAnalysisEffectDefinition(*)(winrt::Windows::Foundation::IActivationFactory const&), SceneAnalysisEffectDefinition>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SceneAnalysisEffectDefinition>(); }))
    {
    }
    inline SpeechCue::SpeechCue() :
        SpeechCue(impl::call_factory_cast<SpeechCue(*)(winrt::Windows::Foundation::IActivationFactory const&), SpeechCue>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SpeechCue>(); }))
    {
    }
    inline TimedMetadataStreamDescriptor::TimedMetadataStreamDescriptor(winrt::Windows::Media::MediaProperties::TimedMetadataEncodingProperties const& encodingProperties) :
        TimedMetadataStreamDescriptor(impl::call_factory<TimedMetadataStreamDescriptor, ITimedMetadataStreamDescriptorFactory>([&](ITimedMetadataStreamDescriptorFactory const& f) { return f.Create(encodingProperties); }))
    {
    }
    inline TimedMetadataTrack::TimedMetadataTrack(param::hstring const& id, param::hstring const& language, winrt::Windows::Media::Core::TimedMetadataKind const& kind) :
        TimedMetadataTrack(impl::call_factory<TimedMetadataTrack, ITimedMetadataTrackFactory>([&](ITimedMetadataTrackFactory const& f) { return f.Create(id, language, kind); }))
    {
    }
    inline TimedTextCue::TimedTextCue() :
        TimedTextCue(impl::call_factory_cast<TimedTextCue(*)(winrt::Windows::Foundation::IActivationFactory const&), TimedTextCue>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<TimedTextCue>(); }))
    {
    }
    inline TimedTextLine::TimedTextLine() :
        TimedTextLine(impl::call_factory_cast<TimedTextLine(*)(winrt::Windows::Foundation::IActivationFactory const&), TimedTextLine>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<TimedTextLine>(); }))
    {
    }
    inline TimedTextRegion::TimedTextRegion() :
        TimedTextRegion(impl::call_factory_cast<TimedTextRegion(*)(winrt::Windows::Foundation::IActivationFactory const&), TimedTextRegion>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<TimedTextRegion>(); }))
    {
    }
    inline auto TimedTextSource::CreateFromStream(winrt::Windows::Storage::Streams::IRandomAccessStream const& stream)
    {
        return impl::call_factory<TimedTextSource, ITimedTextSourceStatics>([&](ITimedTextSourceStatics const& f) { return f.CreateFromStream(stream); });
    }
    inline auto TimedTextSource::CreateFromUri(winrt::Windows::Foundation::Uri const& uri)
    {
        return impl::call_factory<TimedTextSource, ITimedTextSourceStatics>([&](ITimedTextSourceStatics const& f) { return f.CreateFromUri(uri); });
    }
    inline auto TimedTextSource::CreateFromStream(winrt::Windows::Storage::Streams::IRandomAccessStream const& stream, param::hstring const& defaultLanguage)
    {
        return impl::call_factory<TimedTextSource, ITimedTextSourceStatics>([&](ITimedTextSourceStatics const& f) { return f.CreateFromStream(stream, defaultLanguage); });
    }
    inline auto TimedTextSource::CreateFromUri(winrt::Windows::Foundation::Uri const& uri, param::hstring const& defaultLanguage)
    {
        return impl::call_factory<TimedTextSource, ITimedTextSourceStatics>([&](ITimedTextSourceStatics const& f) { return f.CreateFromUri(uri, defaultLanguage); });
    }
    inline auto TimedTextSource::CreateFromStreamWithIndex(winrt::Windows::Storage::Streams::IRandomAccessStream const& stream, winrt::Windows::Storage::Streams::IRandomAccessStream const& indexStream)
    {
        return impl::call_factory<TimedTextSource, ITimedTextSourceStatics2>([&](ITimedTextSourceStatics2 const& f) { return f.CreateFromStreamWithIndex(stream, indexStream); });
    }
    inline auto TimedTextSource::CreateFromUriWithIndex(winrt::Windows::Foundation::Uri const& uri, winrt::Windows::Foundation::Uri const& indexUri)
    {
        return impl::call_factory<TimedTextSource, ITimedTextSourceStatics2>([&](ITimedTextSourceStatics2 const& f) { return f.CreateFromUriWithIndex(uri, indexUri); });
    }
    inline auto TimedTextSource::CreateFromStreamWithIndex(winrt::Windows::Storage::Streams::IRandomAccessStream const& stream, winrt::Windows::Storage::Streams::IRandomAccessStream const& indexStream, param::hstring const& defaultLanguage)
    {
        return impl::call_factory<TimedTextSource, ITimedTextSourceStatics2>([&](ITimedTextSourceStatics2 const& f) { return f.CreateFromStreamWithIndex(stream, indexStream, defaultLanguage); });
    }
    inline auto TimedTextSource::CreateFromUriWithIndex(winrt::Windows::Foundation::Uri const& uri, winrt::Windows::Foundation::Uri const& indexUri, param::hstring const& defaultLanguage)
    {
        return impl::call_factory<TimedTextSource, ITimedTextSourceStatics2>([&](ITimedTextSourceStatics2 const& f) { return f.CreateFromUriWithIndex(uri, indexUri, defaultLanguage); });
    }
    inline TimedTextStyle::TimedTextStyle() :
        TimedTextStyle(impl::call_factory_cast<TimedTextStyle(*)(winrt::Windows::Foundation::IActivationFactory const&), TimedTextStyle>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<TimedTextStyle>(); }))
    {
    }
    inline TimedTextSubformat::TimedTextSubformat() :
        TimedTextSubformat(impl::call_factory_cast<TimedTextSubformat(*)(winrt::Windows::Foundation::IActivationFactory const&), TimedTextSubformat>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<TimedTextSubformat>(); }))
    {
    }
    inline VideoStabilizationEffectDefinition::VideoStabilizationEffectDefinition() :
        VideoStabilizationEffectDefinition(impl::call_factory_cast<VideoStabilizationEffectDefinition(*)(winrt::Windows::Foundation::IActivationFactory const&), VideoStabilizationEffectDefinition>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<VideoStabilizationEffectDefinition>(); }))
    {
    }
    inline VideoStreamDescriptor::VideoStreamDescriptor(winrt::Windows::Media::MediaProperties::VideoEncodingProperties const& encodingProperties) :
        VideoStreamDescriptor(impl::call_factory<VideoStreamDescriptor, IVideoStreamDescriptorFactory>([&](IVideoStreamDescriptorFactory const& f) { return f.Create(encodingProperties); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Media::Core::IAudioStreamDescriptor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IAudioStreamDescriptor2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IAudioStreamDescriptor3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IAudioStreamDescriptorFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IAudioTrack> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IAudioTrackOpenFailedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IAudioTrackSupportInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IChapterCue> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ICodecInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ICodecQuery> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ICodecSubtypesStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IDataCue> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IDataCue2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IFaceDetectedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IFaceDetectionEffect> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IFaceDetectionEffectDefinition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IFaceDetectionEffectFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IHighDynamicRangeControl> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IHighDynamicRangeOutput> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IImageCue> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IInitializeMediaStreamSourceRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ILowLightFusionResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ILowLightFusionStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaBinder> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaBindingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaBindingEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaBindingEventArgs3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaCue> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaCueEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaSource2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaSource3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaSource4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaSource5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaSourceAppServiceConnection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaSourceAppServiceConnectionFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaSourceError> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaSourceOpenOperationCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaSourceStateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaSourceStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaSourceStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaSourceStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaSourceStatics4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaStreamDescriptor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaStreamDescriptor2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSample> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSample2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSampleProtectionProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSampleStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSampleStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSource2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSource3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSource4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSourceClosedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSourceClosedRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSourceFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSourceSampleRenderedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSourceSampleRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSourceSampleRequestDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSourceSampleRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSourceStartingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSourceStartingRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSourceStartingRequestDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequestDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaStreamSourceSwitchStreamsRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMediaTrack> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMseSourceBuffer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMseSourceBufferList> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMseStreamSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMseStreamSource2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IMseStreamSourceStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ISceneAnalysisEffect> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ISceneAnalysisEffectFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ISceneAnalysisEffectFrame2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ISceneAnalyzedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ISingleSelectMediaTrackList> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ISpeechCue> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ITimedMetadataStreamDescriptor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ITimedMetadataStreamDescriptorFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ITimedMetadataTrack> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ITimedMetadataTrack2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ITimedMetadataTrackError> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ITimedMetadataTrackFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ITimedMetadataTrackFailedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ITimedMetadataTrackProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ITimedTextBouten> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ITimedTextCue> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ITimedTextLine> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ITimedTextRegion> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ITimedTextRuby> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ITimedTextSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ITimedTextSourceResolveResultEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ITimedTextSourceStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ITimedTextSourceStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ITimedTextStyle> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ITimedTextStyle2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ITimedTextStyle3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ITimedTextSubformat> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IVideoStabilizationEffect> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IVideoStabilizationEffectEnabledChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IVideoStreamDescriptor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IVideoStreamDescriptor2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IVideoStreamDescriptorFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IVideoTrack> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IVideoTrackOpenFailedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::IVideoTrackSupportInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::AudioStreamDescriptor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::AudioTrack> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::AudioTrackOpenFailedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::AudioTrackSupportInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ChapterCue> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::CodecInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::CodecQuery> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::CodecSubtypes> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::DataCue> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::FaceDetectedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::FaceDetectionEffect> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::FaceDetectionEffectDefinition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::FaceDetectionEffectFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::HighDynamicRangeControl> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::HighDynamicRangeOutput> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::ImageCue> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::InitializeMediaStreamSourceRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::LowLightFusion> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::LowLightFusionResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::MediaBinder> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::MediaBindingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::MediaCueEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::MediaSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::MediaSourceAppServiceConnection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::MediaSourceError> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::MediaSourceOpenOperationCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::MediaSourceStateChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::MediaStreamSample> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::MediaStreamSamplePropertySet> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::MediaStreamSampleProtectionProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::MediaStreamSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::MediaStreamSourceClosedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::MediaStreamSourceClosedRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::MediaStreamSourceSampleRenderedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::MediaStreamSourceSampleRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::MediaStreamSourceSampleRequestDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::MediaStreamSourceSampleRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::MediaStreamSourceStartingEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::MediaStreamSourceStartingRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::MediaStreamSourceStartingRequestDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::MediaStreamSourceSwitchStreamsRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::MediaStreamSourceSwitchStreamsRequestDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::MediaStreamSourceSwitchStreamsRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::MseSourceBuffer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::MseSourceBufferList> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::MseStreamSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::SceneAnalysisEffect> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::SceneAnalysisEffectDefinition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::SceneAnalysisEffectFrame> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::SceneAnalyzedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::SpeechCue> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::TimedMetadataStreamDescriptor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::TimedMetadataTrack> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::TimedMetadataTrackError> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::TimedMetadataTrackFailedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::TimedTextBouten> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::TimedTextCue> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::TimedTextLine> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::TimedTextRegion> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::TimedTextRuby> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::TimedTextSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::TimedTextSourceResolveResultEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::TimedTextStyle> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::TimedTextSubformat> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::VideoStabilizationEffect> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::VideoStabilizationEffectDefinition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::VideoStabilizationEffectEnabledChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::VideoStreamDescriptor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::VideoTrack> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::VideoTrackOpenFailedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::VideoTrackSupportInfo> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
