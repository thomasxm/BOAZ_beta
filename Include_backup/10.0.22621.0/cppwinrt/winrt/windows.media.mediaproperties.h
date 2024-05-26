// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_MediaProperties_H
#define WINRT_Windows_Media_MediaProperties_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Media.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Media.Core.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Media.MediaProperties.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_MediaProperties_IAudioEncodingProperties<D>::Bitrate(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAudioEncodingProperties)->put_Bitrate(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_MediaProperties_IAudioEncodingProperties<D>::Bitrate() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAudioEncodingProperties)->get_Bitrate(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_MediaProperties_IAudioEncodingProperties<D>::ChannelCount(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAudioEncodingProperties)->put_ChannelCount(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_MediaProperties_IAudioEncodingProperties<D>::ChannelCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAudioEncodingProperties)->get_ChannelCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_MediaProperties_IAudioEncodingProperties<D>::SampleRate(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAudioEncodingProperties)->put_SampleRate(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_MediaProperties_IAudioEncodingProperties<D>::SampleRate() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAudioEncodingProperties)->get_SampleRate(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_MediaProperties_IAudioEncodingProperties<D>::BitsPerSample(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAudioEncodingProperties)->put_BitsPerSample(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_MediaProperties_IAudioEncodingProperties<D>::BitsPerSample() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAudioEncodingProperties)->get_BitsPerSample(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_MediaProperties_IAudioEncodingProperties2<D>::IsSpatial() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAudioEncodingProperties2)->get_IsSpatial(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::AudioEncodingProperties) consume_Windows_Media_MediaProperties_IAudioEncodingProperties3<D>::Copy() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAudioEncodingProperties3)->Copy(&result));
        return winrt::Windows::Media::MediaProperties::AudioEncodingProperties{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::AudioEncodingProperties) consume_Windows_Media_MediaProperties_IAudioEncodingPropertiesStatics<D>::CreateAac(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics)->CreateAac(sampleRate, channelCount, bitrate, &value));
        return winrt::Windows::Media::MediaProperties::AudioEncodingProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::AudioEncodingProperties) consume_Windows_Media_MediaProperties_IAudioEncodingPropertiesStatics<D>::CreateAacAdts(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics)->CreateAacAdts(sampleRate, channelCount, bitrate, &value));
        return winrt::Windows::Media::MediaProperties::AudioEncodingProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::AudioEncodingProperties) consume_Windows_Media_MediaProperties_IAudioEncodingPropertiesStatics<D>::CreateMp3(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics)->CreateMp3(sampleRate, channelCount, bitrate, &value));
        return winrt::Windows::Media::MediaProperties::AudioEncodingProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::AudioEncodingProperties) consume_Windows_Media_MediaProperties_IAudioEncodingPropertiesStatics<D>::CreatePcm(uint32_t sampleRate, uint32_t channelCount, uint32_t bitsPerSample) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics)->CreatePcm(sampleRate, channelCount, bitsPerSample, &value));
        return winrt::Windows::Media::MediaProperties::AudioEncodingProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::AudioEncodingProperties) consume_Windows_Media_MediaProperties_IAudioEncodingPropertiesStatics<D>::CreateWma(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics)->CreateWma(sampleRate, channelCount, bitrate, &value));
        return winrt::Windows::Media::MediaProperties::AudioEncodingProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::AudioEncodingProperties) consume_Windows_Media_MediaProperties_IAudioEncodingPropertiesStatics2<D>::CreateAlac(uint32_t sampleRate, uint32_t channelCount, uint32_t bitsPerSample) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics2)->CreateAlac(sampleRate, channelCount, bitsPerSample, &value));
        return winrt::Windows::Media::MediaProperties::AudioEncodingProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::AudioEncodingProperties) consume_Windows_Media_MediaProperties_IAudioEncodingPropertiesStatics2<D>::CreateFlac(uint32_t sampleRate, uint32_t channelCount, uint32_t bitsPerSample) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics2)->CreateFlac(sampleRate, channelCount, bitsPerSample, &value));
        return winrt::Windows::Media::MediaProperties::AudioEncodingProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_MediaProperties_IAudioEncodingPropertiesWithFormatUserData<D>::SetFormatUserData(array_view<uint8_t const> value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAudioEncodingPropertiesWithFormatUserData)->SetFormatUserData(value.size(), get_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_MediaProperties_IAudioEncodingPropertiesWithFormatUserData<D>::GetFormatUserData(com_array<uint8_t>& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAudioEncodingPropertiesWithFormatUserData)->GetFormatUserData(impl::put_size_abi(value), put_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IAv1ProfileIdsStatics<D>::MainChromaSubsampling420BitDepth8() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAv1ProfileIdsStatics)->get_MainChromaSubsampling420BitDepth8(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IAv1ProfileIdsStatics<D>::MainChromaSubsampling420BitDepth10() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAv1ProfileIdsStatics)->get_MainChromaSubsampling420BitDepth10(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IAv1ProfileIdsStatics<D>::MainChromaSubsampling400BitDepth8() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAv1ProfileIdsStatics)->get_MainChromaSubsampling400BitDepth8(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IAv1ProfileIdsStatics<D>::MainChromaSubsampling400BitDepth10() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAv1ProfileIdsStatics)->get_MainChromaSubsampling400BitDepth10(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IAv1ProfileIdsStatics<D>::HighChromaSubsampling444BitDepth8() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAv1ProfileIdsStatics)->get_HighChromaSubsampling444BitDepth8(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IAv1ProfileIdsStatics<D>::HighChromaSubsampling444BitDepth10() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAv1ProfileIdsStatics)->get_HighChromaSubsampling444BitDepth10(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IAv1ProfileIdsStatics<D>::ProfessionalChromaSubsampling420BitDepth12() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAv1ProfileIdsStatics)->get_ProfessionalChromaSubsampling420BitDepth12(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IAv1ProfileIdsStatics<D>::ProfessionalChromaSubsampling400BitDepth12() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAv1ProfileIdsStatics)->get_ProfessionalChromaSubsampling400BitDepth12(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IAv1ProfileIdsStatics<D>::ProfessionalChromaSubsampling444BitDepth12() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAv1ProfileIdsStatics)->get_ProfessionalChromaSubsampling444BitDepth12(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IAv1ProfileIdsStatics<D>::ProfessionalChromaSubsampling422BitDepth8() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAv1ProfileIdsStatics)->get_ProfessionalChromaSubsampling422BitDepth8(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IAv1ProfileIdsStatics<D>::ProfessionalChromaSubsampling422BitDepth10() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAv1ProfileIdsStatics)->get_ProfessionalChromaSubsampling422BitDepth10(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IAv1ProfileIdsStatics<D>::ProfessionalChromaSubsampling422BitDepth12() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IAv1ProfileIdsStatics)->get_ProfessionalChromaSubsampling422BitDepth12(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::ContainerEncodingProperties) consume_Windows_Media_MediaProperties_IContainerEncodingProperties2<D>::Copy() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IContainerEncodingProperties2)->Copy(&result));
        return winrt::Windows::Media::MediaProperties::ContainerEncodingProperties{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IH264ProfileIdsStatics<D>::ConstrainedBaseline() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IH264ProfileIdsStatics)->get_ConstrainedBaseline(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IH264ProfileIdsStatics<D>::Baseline() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IH264ProfileIdsStatics)->get_Baseline(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IH264ProfileIdsStatics<D>::Extended() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IH264ProfileIdsStatics)->get_Extended(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IH264ProfileIdsStatics<D>::Main() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IH264ProfileIdsStatics)->get_Main(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IH264ProfileIdsStatics<D>::High() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IH264ProfileIdsStatics)->get_High(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IH264ProfileIdsStatics<D>::High10() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IH264ProfileIdsStatics)->get_High10(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IH264ProfileIdsStatics<D>::High422() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IH264ProfileIdsStatics)->get_High422(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IH264ProfileIdsStatics<D>::High444() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IH264ProfileIdsStatics)->get_High444(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IH264ProfileIdsStatics<D>::StereoHigh() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IH264ProfileIdsStatics)->get_StereoHigh(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IH264ProfileIdsStatics<D>::MultiviewHigh() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IH264ProfileIdsStatics)->get_MultiviewHigh(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IHevcProfileIdsStatics<D>::MainChromaSubsampling420BitDepth8() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IHevcProfileIdsStatics)->get_MainChromaSubsampling420BitDepth8(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IHevcProfileIdsStatics<D>::MainChromaSubsampling420BitDepth10() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IHevcProfileIdsStatics)->get_MainChromaSubsampling420BitDepth10(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IHevcProfileIdsStatics<D>::MainChromaSubsampling420BitDepth12() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IHevcProfileIdsStatics)->get_MainChromaSubsampling420BitDepth12(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IHevcProfileIdsStatics<D>::MainChromaSubsampling422BitDepth10() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IHevcProfileIdsStatics)->get_MainChromaSubsampling422BitDepth10(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IHevcProfileIdsStatics<D>::MainChromaSubsampling422BitDepth12() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IHevcProfileIdsStatics)->get_MainChromaSubsampling422BitDepth12(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IHevcProfileIdsStatics<D>::MainChromaSubsampling444BitDepth8() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IHevcProfileIdsStatics)->get_MainChromaSubsampling444BitDepth8(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IHevcProfileIdsStatics<D>::MainChromaSubsampling444BitDepth10() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IHevcProfileIdsStatics)->get_MainChromaSubsampling444BitDepth10(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IHevcProfileIdsStatics<D>::MainChromaSubsampling444BitDepth12() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IHevcProfileIdsStatics)->get_MainChromaSubsampling444BitDepth12(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IHevcProfileIdsStatics<D>::MonochromeBitDepth12() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IHevcProfileIdsStatics)->get_MonochromeBitDepth12(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IHevcProfileIdsStatics<D>::MonochromeBitDepth16() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IHevcProfileIdsStatics)->get_MonochromeBitDepth16(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IHevcProfileIdsStatics<D>::MainIntraChromaSubsampling420BitDepth8() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IHevcProfileIdsStatics)->get_MainIntraChromaSubsampling420BitDepth8(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IHevcProfileIdsStatics<D>::MainIntraChromaSubsampling420BitDepth10() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IHevcProfileIdsStatics)->get_MainIntraChromaSubsampling420BitDepth10(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IHevcProfileIdsStatics<D>::MainIntraChromaSubsampling420BitDepth12() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IHevcProfileIdsStatics)->get_MainIntraChromaSubsampling420BitDepth12(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IHevcProfileIdsStatics<D>::MainIntraChromaSubsampling422BitDepth10() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IHevcProfileIdsStatics)->get_MainIntraChromaSubsampling422BitDepth10(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IHevcProfileIdsStatics<D>::MainIntraChromaSubsampling422BitDepth12() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IHevcProfileIdsStatics)->get_MainIntraChromaSubsampling422BitDepth12(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IHevcProfileIdsStatics<D>::MainIntraChromaSubsampling444BitDepth8() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IHevcProfileIdsStatics)->get_MainIntraChromaSubsampling444BitDepth8(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IHevcProfileIdsStatics<D>::MainIntraChromaSubsampling444BitDepth10() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IHevcProfileIdsStatics)->get_MainIntraChromaSubsampling444BitDepth10(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IHevcProfileIdsStatics<D>::MainIntraChromaSubsampling444BitDepth12() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IHevcProfileIdsStatics)->get_MainIntraChromaSubsampling444BitDepth12(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IHevcProfileIdsStatics<D>::MainIntraChromaSubsampling444BitDepth16() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IHevcProfileIdsStatics)->get_MainIntraChromaSubsampling444BitDepth16(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IHevcProfileIdsStatics<D>::MainStillChromaSubsampling420BitDepth8() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IHevcProfileIdsStatics)->get_MainStillChromaSubsampling420BitDepth8(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IHevcProfileIdsStatics<D>::MainStillChromaSubsampling444BitDepth8() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IHevcProfileIdsStatics)->get_MainStillChromaSubsampling444BitDepth8(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IHevcProfileIdsStatics<D>::MainStillChromaSubsampling444BitDepth16() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IHevcProfileIdsStatics)->get_MainStillChromaSubsampling444BitDepth16(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_MediaProperties_IImageEncodingProperties<D>::Width(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IImageEncodingProperties)->put_Width(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_MediaProperties_IImageEncodingProperties<D>::Width() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IImageEncodingProperties)->get_Width(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_MediaProperties_IImageEncodingProperties<D>::Height(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IImageEncodingProperties)->put_Height(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_MediaProperties_IImageEncodingProperties<D>::Height() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IImageEncodingProperties)->get_Height(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::ImageEncodingProperties) consume_Windows_Media_MediaProperties_IImageEncodingProperties2<D>::Copy() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IImageEncodingProperties2)->Copy(&result));
        return winrt::Windows::Media::MediaProperties::ImageEncodingProperties{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::ImageEncodingProperties) consume_Windows_Media_MediaProperties_IImageEncodingPropertiesStatics<D>::CreateJpeg() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IImageEncodingPropertiesStatics)->CreateJpeg(&value));
        return winrt::Windows::Media::MediaProperties::ImageEncodingProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::ImageEncodingProperties) consume_Windows_Media_MediaProperties_IImageEncodingPropertiesStatics<D>::CreatePng() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IImageEncodingPropertiesStatics)->CreatePng(&value));
        return winrt::Windows::Media::MediaProperties::ImageEncodingProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::ImageEncodingProperties) consume_Windows_Media_MediaProperties_IImageEncodingPropertiesStatics<D>::CreateJpegXR() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IImageEncodingPropertiesStatics)->CreateJpegXR(&value));
        return winrt::Windows::Media::MediaProperties::ImageEncodingProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::ImageEncodingProperties) consume_Windows_Media_MediaProperties_IImageEncodingPropertiesStatics2<D>::CreateUncompressed(winrt::Windows::Media::MediaProperties::MediaPixelFormat const& format) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IImageEncodingPropertiesStatics2)->CreateUncompressed(static_cast<int32_t>(format), &value));
        return winrt::Windows::Media::MediaProperties::ImageEncodingProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::ImageEncodingProperties) consume_Windows_Media_MediaProperties_IImageEncodingPropertiesStatics2<D>::CreateBmp() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IImageEncodingPropertiesStatics2)->CreateBmp(&value));
        return winrt::Windows::Media::MediaProperties::ImageEncodingProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::ImageEncodingProperties) consume_Windows_Media_MediaProperties_IImageEncodingPropertiesStatics3<D>::CreateHeif() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IImageEncodingPropertiesStatics3)->CreateHeif(&result));
        return winrt::Windows::Media::MediaProperties::ImageEncodingProperties{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_MediaProperties_IMediaEncodingProfile<D>::Audio(winrt::Windows::Media::MediaProperties::AudioEncodingProperties const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProfile)->put_Audio(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::AudioEncodingProperties) consume_Windows_Media_MediaProperties_IMediaEncodingProfile<D>::Audio() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProfile)->get_Audio(&value));
        return winrt::Windows::Media::MediaProperties::AudioEncodingProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_MediaProperties_IMediaEncodingProfile<D>::Video(winrt::Windows::Media::MediaProperties::VideoEncodingProperties const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProfile)->put_Video(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::VideoEncodingProperties) consume_Windows_Media_MediaProperties_IMediaEncodingProfile<D>::Video() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProfile)->get_Video(&value));
        return winrt::Windows::Media::MediaProperties::VideoEncodingProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_MediaProperties_IMediaEncodingProfile<D>::Container(winrt::Windows::Media::MediaProperties::ContainerEncodingProperties const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProfile)->put_Container(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::ContainerEncodingProperties) consume_Windows_Media_MediaProperties_IMediaEncodingProfile<D>::Container() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProfile)->get_Container(&value));
        return winrt::Windows::Media::MediaProperties::ContainerEncodingProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_MediaProperties_IMediaEncodingProfile2<D>::SetAudioTracks(param::iterable<winrt::Windows::Media::Core::AudioStreamDescriptor> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProfile2)->SetAudioTracks(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Media::Core::AudioStreamDescriptor>) consume_Windows_Media_MediaProperties_IMediaEncodingProfile2<D>::GetAudioTracks() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProfile2)->GetAudioTracks(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Media::Core::AudioStreamDescriptor>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_MediaProperties_IMediaEncodingProfile2<D>::SetVideoTracks(param::iterable<winrt::Windows::Media::Core::VideoStreamDescriptor> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProfile2)->SetVideoTracks(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Media::Core::VideoStreamDescriptor>) consume_Windows_Media_MediaProperties_IMediaEncodingProfile2<D>::GetVideoTracks() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProfile2)->GetVideoTracks(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Media::Core::VideoStreamDescriptor>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_MediaProperties_IMediaEncodingProfile3<D>::SetTimedMetadataTracks(param::iterable<winrt::Windows::Media::Core::TimedMetadataStreamDescriptor> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProfile3)->SetTimedMetadataTracks(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Media::Core::TimedMetadataStreamDescriptor>) consume_Windows_Media_MediaProperties_IMediaEncodingProfile3<D>::GetTimedMetadataTracks() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProfile3)->GetTimedMetadataTracks(&result));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Media::Core::TimedMetadataStreamDescriptor>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::MediaEncodingProfile) consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics<D>::CreateM4a(winrt::Windows::Media::MediaProperties::AudioEncodingQuality const& quality) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics)->CreateM4a(static_cast<int32_t>(quality), &value));
        return winrt::Windows::Media::MediaProperties::MediaEncodingProfile{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::MediaEncodingProfile) consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics<D>::CreateMp3(winrt::Windows::Media::MediaProperties::AudioEncodingQuality const& quality) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics)->CreateMp3(static_cast<int32_t>(quality), &value));
        return winrt::Windows::Media::MediaProperties::MediaEncodingProfile{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::MediaEncodingProfile) consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics<D>::CreateWma(winrt::Windows::Media::MediaProperties::AudioEncodingQuality const& quality) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics)->CreateWma(static_cast<int32_t>(quality), &value));
        return winrt::Windows::Media::MediaProperties::MediaEncodingProfile{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::MediaEncodingProfile) consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics<D>::CreateMp4(winrt::Windows::Media::MediaProperties::VideoEncodingQuality const& quality) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics)->CreateMp4(static_cast<int32_t>(quality), &value));
        return winrt::Windows::Media::MediaProperties::MediaEncodingProfile{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::MediaEncodingProfile) consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics<D>::CreateWmv(winrt::Windows::Media::MediaProperties::VideoEncodingQuality const& quality) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics)->CreateWmv(static_cast<int32_t>(quality), &value));
        return winrt::Windows::Media::MediaProperties::MediaEncodingProfile{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::MediaProperties::MediaEncodingProfile>) consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics<D>::CreateFromFileAsync(winrt::Windows::Storage::IStorageFile const& file) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics)->CreateFromFileAsync(*(void**)(&file), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::MediaProperties::MediaEncodingProfile>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::MediaProperties::MediaEncodingProfile>) consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics<D>::CreateFromStreamAsync(winrt::Windows::Storage::Streams::IRandomAccessStream const& stream) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics)->CreateFromStreamAsync(*(void**)(&stream), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::MediaProperties::MediaEncodingProfile>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::MediaEncodingProfile) consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics2<D>::CreateWav(winrt::Windows::Media::MediaProperties::AudioEncodingQuality const& quality) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics2)->CreateWav(static_cast<int32_t>(quality), &value));
        return winrt::Windows::Media::MediaProperties::MediaEncodingProfile{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::MediaEncodingProfile) consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics2<D>::CreateAvi(winrt::Windows::Media::MediaProperties::VideoEncodingQuality const& quality) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics2)->CreateAvi(static_cast<int32_t>(quality), &value));
        return winrt::Windows::Media::MediaProperties::MediaEncodingProfile{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::MediaEncodingProfile) consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics3<D>::CreateAlac(winrt::Windows::Media::MediaProperties::AudioEncodingQuality const& quality) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics3)->CreateAlac(static_cast<int32_t>(quality), &value));
        return winrt::Windows::Media::MediaProperties::MediaEncodingProfile{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::MediaEncodingProfile) consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics3<D>::CreateFlac(winrt::Windows::Media::MediaProperties::AudioEncodingQuality const& quality) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics3)->CreateFlac(static_cast<int32_t>(quality), &value));
        return winrt::Windows::Media::MediaProperties::MediaEncodingProfile{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::MediaEncodingProfile) consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics3<D>::CreateHevc(winrt::Windows::Media::MediaProperties::VideoEncodingQuality const& quality) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics3)->CreateHevc(static_cast<int32_t>(quality), &value));
        return winrt::Windows::Media::MediaProperties::MediaEncodingProfile{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::MediaEncodingProfile) consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics4<D>::CreateVp9(winrt::Windows::Media::MediaProperties::VideoEncodingQuality const& quality) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics4)->CreateVp9(static_cast<int32_t>(quality), &result));
        return winrt::Windows::Media::MediaProperties::MediaEncodingProfile{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::MediaEncodingProfile) consume_Windows_Media_MediaProperties_IMediaEncodingProfileStatics4<D>::CreateAv1(winrt::Windows::Media::MediaProperties::VideoEncodingQuality const& quality) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics4)->CreateAv1(static_cast<int32_t>(quality), &result));
        return winrt::Windows::Media::MediaProperties::MediaEncodingProfile{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::MediaPropertySet) consume_Windows_Media_MediaProperties_IMediaEncodingProperties<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProperties)->get_Properties(&value));
        return winrt::Windows::Media::MediaProperties::MediaPropertySet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingProperties<D>::Type() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProperties)->get_Type(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_MediaProperties_IMediaEncodingProperties<D>::Subtype(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProperties)->put_Subtype(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingProperties<D>::Subtype() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingProperties)->get_Subtype(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Aac() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Aac(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::AacAdts() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_AacAdts(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Ac3() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Ac3(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::AmrNb() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_AmrNb(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::AmrWb() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_AmrWb(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Argb32() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Argb32(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Asf() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Asf(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Avi() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Avi(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Bgra8() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Bgra8(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Bmp() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Bmp(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Eac3() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Eac3(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Float() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Float(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Gif() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Gif(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::H263() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_H263(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::H264() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_H264(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::H264Es() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_H264Es(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Hevc() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Hevc(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::HevcEs() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_HevcEs(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Iyuv() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Iyuv(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Jpeg() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Jpeg(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::JpegXr() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_JpegXr(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Mjpg() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Mjpg(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Mpeg() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Mpeg(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Mpeg1() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Mpeg1(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Mpeg2() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Mpeg2(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Mp3() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Mp3(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Mpeg4() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Mpeg4(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Nv12() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Nv12(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Pcm() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Pcm(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Png() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Png(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Rgb24() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Rgb24(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Rgb32() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Rgb32(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Tiff() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Tiff(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Wave() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Wave(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Wma8() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Wma8(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Wma9() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Wma9(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Wmv3() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Wmv3(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Wvc1() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Wvc1(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Yuy2() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Yuy2(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics<D>::Yv12() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics)->get_Yv12(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics2<D>::Vp9() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics2)->get_Vp9(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics2<D>::L8() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics2)->get_L8(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics2<D>::L16() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics2)->get_L16(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics2<D>::D16() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics2)->get_D16(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics3<D>::Alac() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics3)->get_Alac(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics3<D>::Flac() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics3)->get_Flac(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics4<D>::P010() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics4)->get_P010(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics5<D>::Heif() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics5)->get_Heif(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics6<D>::Pgs() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics6)->get_Pgs(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics6<D>::Srt() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics6)->get_Srt(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics6<D>::Ssa() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics6)->get_Ssa(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics6<D>::VobSub() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics6)->get_VobSub(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_MediaProperties_IMediaEncodingSubtypesStatics7<D>::Av1() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics7)->get_Av1(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_MediaProperties_IMediaRatio<D>::Numerator(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaRatio)->put_Numerator(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_MediaProperties_IMediaRatio<D>::Numerator() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaRatio)->get_Numerator(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_MediaProperties_IMediaRatio<D>::Denominator(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaRatio)->put_Denominator(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_MediaProperties_IMediaRatio<D>::Denominator() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMediaRatio)->get_Denominator(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IMpeg2ProfileIdsStatics<D>::Simple() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMpeg2ProfileIdsStatics)->get_Simple(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IMpeg2ProfileIdsStatics<D>::Main() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMpeg2ProfileIdsStatics)->get_Main(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IMpeg2ProfileIdsStatics<D>::SignalNoiseRatioScalable() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMpeg2ProfileIdsStatics)->get_SignalNoiseRatioScalable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IMpeg2ProfileIdsStatics<D>::SpatiallyScalable() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMpeg2ProfileIdsStatics)->get_SpatiallyScalable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IMpeg2ProfileIdsStatics<D>::High() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IMpeg2ProfileIdsStatics)->get_High(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_MediaProperties_ITimedMetadataEncodingProperties<D>::SetFormatUserData(array_view<uint8_t const> value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::ITimedMetadataEncodingProperties)->SetFormatUserData(value.size(), get_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_MediaProperties_ITimedMetadataEncodingProperties<D>::GetFormatUserData(com_array<uint8_t>& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::ITimedMetadataEncodingProperties)->GetFormatUserData(impl::put_size_abi(value), put_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::TimedMetadataEncodingProperties) consume_Windows_Media_MediaProperties_ITimedMetadataEncodingProperties<D>::Copy() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::ITimedMetadataEncodingProperties)->Copy(&result));
        return winrt::Windows::Media::MediaProperties::TimedMetadataEncodingProperties{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::TimedMetadataEncodingProperties) consume_Windows_Media_MediaProperties_ITimedMetadataEncodingPropertiesStatics<D>::CreatePgs() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::ITimedMetadataEncodingPropertiesStatics)->CreatePgs(&result));
        return winrt::Windows::Media::MediaProperties::TimedMetadataEncodingProperties{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::TimedMetadataEncodingProperties) consume_Windows_Media_MediaProperties_ITimedMetadataEncodingPropertiesStatics<D>::CreateSrt() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::ITimedMetadataEncodingPropertiesStatics)->CreateSrt(&result));
        return winrt::Windows::Media::MediaProperties::TimedMetadataEncodingProperties{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::TimedMetadataEncodingProperties) consume_Windows_Media_MediaProperties_ITimedMetadataEncodingPropertiesStatics<D>::CreateSsa(array_view<uint8_t const> formatUserData) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::ITimedMetadataEncodingPropertiesStatics)->CreateSsa(formatUserData.size(), get_abi(formatUserData), &result));
        return winrt::Windows::Media::MediaProperties::TimedMetadataEncodingProperties{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::TimedMetadataEncodingProperties) consume_Windows_Media_MediaProperties_ITimedMetadataEncodingPropertiesStatics<D>::CreateVobSub(array_view<uint8_t const> formatUserData) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::ITimedMetadataEncodingPropertiesStatics)->CreateVobSub(formatUserData.size(), get_abi(formatUserData), &result));
        return winrt::Windows::Media::MediaProperties::TimedMetadataEncodingProperties{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_MediaProperties_IVideoEncodingProperties<D>::Bitrate(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IVideoEncodingProperties)->put_Bitrate(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_MediaProperties_IVideoEncodingProperties<D>::Bitrate() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IVideoEncodingProperties)->get_Bitrate(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_MediaProperties_IVideoEncodingProperties<D>::Width(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IVideoEncodingProperties)->put_Width(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_MediaProperties_IVideoEncodingProperties<D>::Width() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IVideoEncodingProperties)->get_Width(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_MediaProperties_IVideoEncodingProperties<D>::Height(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IVideoEncodingProperties)->put_Height(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_MediaProperties_IVideoEncodingProperties<D>::Height() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IVideoEncodingProperties)->get_Height(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::MediaRatio) consume_Windows_Media_MediaProperties_IVideoEncodingProperties<D>::FrameRate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IVideoEncodingProperties)->get_FrameRate(&value));
        return winrt::Windows::Media::MediaProperties::MediaRatio{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::MediaRatio) consume_Windows_Media_MediaProperties_IVideoEncodingProperties<D>::PixelAspectRatio() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IVideoEncodingProperties)->get_PixelAspectRatio(&value));
        return winrt::Windows::Media::MediaProperties::MediaRatio{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_MediaProperties_IVideoEncodingProperties2<D>::SetFormatUserData(array_view<uint8_t const> value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IVideoEncodingProperties2)->SetFormatUserData(value.size(), get_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_MediaProperties_IVideoEncodingProperties2<D>::GetFormatUserData(com_array<uint8_t>& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IVideoEncodingProperties2)->GetFormatUserData(impl::put_size_abi(value), put_abi(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_MediaProperties_IVideoEncodingProperties2<D>::ProfileId(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IVideoEncodingProperties2)->put_ProfileId(value));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IVideoEncodingProperties2<D>::ProfileId() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IVideoEncodingProperties2)->get_ProfileId(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::StereoscopicVideoPackingMode) consume_Windows_Media_MediaProperties_IVideoEncodingProperties3<D>::StereoscopicVideoPackingMode() const
    {
        winrt::Windows::Media::MediaProperties::StereoscopicVideoPackingMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IVideoEncodingProperties3)->get_StereoscopicVideoPackingMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::SphericalVideoFrameFormat) consume_Windows_Media_MediaProperties_IVideoEncodingProperties4<D>::SphericalVideoFrameFormat() const
    {
        winrt::Windows::Media::MediaProperties::SphericalVideoFrameFormat value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IVideoEncodingProperties4)->get_SphericalVideoFrameFormat(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::VideoEncodingProperties) consume_Windows_Media_MediaProperties_IVideoEncodingProperties5<D>::Copy() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IVideoEncodingProperties5)->Copy(&result));
        return winrt::Windows::Media::MediaProperties::VideoEncodingProperties{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::VideoEncodingProperties) consume_Windows_Media_MediaProperties_IVideoEncodingPropertiesStatics<D>::CreateH264() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics)->CreateH264(&value));
        return winrt::Windows::Media::MediaProperties::VideoEncodingProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::VideoEncodingProperties) consume_Windows_Media_MediaProperties_IVideoEncodingPropertiesStatics<D>::CreateMpeg2() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics)->CreateMpeg2(&value));
        return winrt::Windows::Media::MediaProperties::VideoEncodingProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::VideoEncodingProperties) consume_Windows_Media_MediaProperties_IVideoEncodingPropertiesStatics<D>::CreateUncompressed(param::hstring const& subtype, uint32_t width, uint32_t height) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics)->CreateUncompressed(*(void**)(&subtype), width, height, &value));
        return winrt::Windows::Media::MediaProperties::VideoEncodingProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::VideoEncodingProperties) consume_Windows_Media_MediaProperties_IVideoEncodingPropertiesStatics2<D>::CreateHevc() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics2)->CreateHevc(&value));
        return winrt::Windows::Media::MediaProperties::VideoEncodingProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::VideoEncodingProperties) consume_Windows_Media_MediaProperties_IVideoEncodingPropertiesStatics3<D>::CreateVp9() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics3)->CreateVp9(&result));
        return winrt::Windows::Media::MediaProperties::VideoEncodingProperties{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::VideoEncodingProperties) consume_Windows_Media_MediaProperties_IVideoEncodingPropertiesStatics3<D>::CreateAv1() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics3)->CreateAv1(&result));
        return winrt::Windows::Media::MediaProperties::VideoEncodingProperties{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IVp9ProfileIdsStatics<D>::Profile0ChromaSubsampling420BitDepth8() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IVp9ProfileIdsStatics)->get_Profile0ChromaSubsampling420BitDepth8(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IVp9ProfileIdsStatics<D>::Profile2ChromaSubsampling420BitDepth10() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IVp9ProfileIdsStatics)->get_Profile2ChromaSubsampling420BitDepth10(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_MediaProperties_IVp9ProfileIdsStatics<D>::Profile2ChromaSubsampling420BitDepth12() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::MediaProperties::IVp9ProfileIdsStatics)->get_Profile2ChromaSubsampling420BitDepth12(&value));
        return value;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IAudioEncodingProperties> : produce_base<D, winrt::Windows::Media::MediaProperties::IAudioEncodingProperties>
    {
        int32_t __stdcall put_Bitrate(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Bitrate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Bitrate(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Bitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ChannelCount(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ChannelCount(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ChannelCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ChannelCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SampleRate(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SampleRate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SampleRate(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().SampleRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_BitsPerSample(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().BitsPerSample(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BitsPerSample(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().BitsPerSample());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IAudioEncodingProperties2> : produce_base<D, winrt::Windows::Media::MediaProperties::IAudioEncodingProperties2>
    {
        int32_t __stdcall get_IsSpatial(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSpatial());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IAudioEncodingProperties3> : produce_base<D, winrt::Windows::Media::MediaProperties::IAudioEncodingProperties3>
    {
        int32_t __stdcall Copy(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().Copy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics> : produce_base<D, winrt::Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics>
    {
        int32_t __stdcall CreateAac(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().CreateAac(sampleRate, channelCount, bitrate));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateAacAdts(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().CreateAacAdts(sampleRate, channelCount, bitrate));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateMp3(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().CreateMp3(sampleRate, channelCount, bitrate));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreatePcm(uint32_t sampleRate, uint32_t channelCount, uint32_t bitsPerSample, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().CreatePcm(sampleRate, channelCount, bitsPerSample));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWma(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().CreateWma(sampleRate, channelCount, bitrate));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics2> : produce_base<D, winrt::Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics2>
    {
        int32_t __stdcall CreateAlac(uint32_t sampleRate, uint32_t channelCount, uint32_t bitsPerSample, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().CreateAlac(sampleRate, channelCount, bitsPerSample));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFlac(uint32_t sampleRate, uint32_t channelCount, uint32_t bitsPerSample, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().CreateFlac(sampleRate, channelCount, bitsPerSample));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IAudioEncodingPropertiesWithFormatUserData> : produce_base<D, winrt::Windows::Media::MediaProperties::IAudioEncodingPropertiesWithFormatUserData>
    {
        int32_t __stdcall SetFormatUserData(uint32_t __valueSize, uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetFormatUserData(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(value), reinterpret_cast<uint8_t const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetFormatUserData(uint32_t* __valueSize, uint8_t** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            this->shim().GetFormatUserData(detach_abi<uint8_t>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IAv1ProfileIdsStatics> : produce_base<D, winrt::Windows::Media::MediaProperties::IAv1ProfileIdsStatics>
    {
        int32_t __stdcall get_MainChromaSubsampling420BitDepth8(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MainChromaSubsampling420BitDepth8());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MainChromaSubsampling420BitDepth10(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MainChromaSubsampling420BitDepth10());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MainChromaSubsampling400BitDepth8(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MainChromaSubsampling400BitDepth8());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MainChromaSubsampling400BitDepth10(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MainChromaSubsampling400BitDepth10());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HighChromaSubsampling444BitDepth8(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().HighChromaSubsampling444BitDepth8());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HighChromaSubsampling444BitDepth10(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().HighChromaSubsampling444BitDepth10());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProfessionalChromaSubsampling420BitDepth12(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().ProfessionalChromaSubsampling420BitDepth12());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProfessionalChromaSubsampling400BitDepth12(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().ProfessionalChromaSubsampling400BitDepth12());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProfessionalChromaSubsampling444BitDepth12(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().ProfessionalChromaSubsampling444BitDepth12());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProfessionalChromaSubsampling422BitDepth8(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().ProfessionalChromaSubsampling422BitDepth8());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProfessionalChromaSubsampling422BitDepth10(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().ProfessionalChromaSubsampling422BitDepth10());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProfessionalChromaSubsampling422BitDepth12(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().ProfessionalChromaSubsampling422BitDepth12());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IContainerEncodingProperties> : produce_base<D, winrt::Windows::Media::MediaProperties::IContainerEncodingProperties>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IContainerEncodingProperties2> : produce_base<D, winrt::Windows::Media::MediaProperties::IContainerEncodingProperties2>
    {
        int32_t __stdcall Copy(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::MediaProperties::ContainerEncodingProperties>(this->shim().Copy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IH264ProfileIdsStatics> : produce_base<D, winrt::Windows::Media::MediaProperties::IH264ProfileIdsStatics>
    {
        int32_t __stdcall get_ConstrainedBaseline(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().ConstrainedBaseline());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Baseline(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Baseline());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Extended(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Extended());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Main(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Main());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_High(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().High());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_High10(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().High10());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_High422(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().High422());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_High444(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().High444());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StereoHigh(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().StereoHigh());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MultiviewHigh(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MultiviewHigh());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IHevcProfileIdsStatics> : produce_base<D, winrt::Windows::Media::MediaProperties::IHevcProfileIdsStatics>
    {
        int32_t __stdcall get_MainChromaSubsampling420BitDepth8(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MainChromaSubsampling420BitDepth8());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MainChromaSubsampling420BitDepth10(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MainChromaSubsampling420BitDepth10());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MainChromaSubsampling420BitDepth12(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MainChromaSubsampling420BitDepth12());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MainChromaSubsampling422BitDepth10(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MainChromaSubsampling422BitDepth10());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MainChromaSubsampling422BitDepth12(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MainChromaSubsampling422BitDepth12());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MainChromaSubsampling444BitDepth8(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MainChromaSubsampling444BitDepth8());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MainChromaSubsampling444BitDepth10(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MainChromaSubsampling444BitDepth10());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MainChromaSubsampling444BitDepth12(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MainChromaSubsampling444BitDepth12());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MonochromeBitDepth12(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MonochromeBitDepth12());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MonochromeBitDepth16(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MonochromeBitDepth16());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MainIntraChromaSubsampling420BitDepth8(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MainIntraChromaSubsampling420BitDepth8());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MainIntraChromaSubsampling420BitDepth10(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MainIntraChromaSubsampling420BitDepth10());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MainIntraChromaSubsampling420BitDepth12(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MainIntraChromaSubsampling420BitDepth12());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MainIntraChromaSubsampling422BitDepth10(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MainIntraChromaSubsampling422BitDepth10());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MainIntraChromaSubsampling422BitDepth12(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MainIntraChromaSubsampling422BitDepth12());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MainIntraChromaSubsampling444BitDepth8(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MainIntraChromaSubsampling444BitDepth8());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MainIntraChromaSubsampling444BitDepth10(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MainIntraChromaSubsampling444BitDepth10());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MainIntraChromaSubsampling444BitDepth12(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MainIntraChromaSubsampling444BitDepth12());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MainIntraChromaSubsampling444BitDepth16(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MainIntraChromaSubsampling444BitDepth16());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MainStillChromaSubsampling420BitDepth8(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MainStillChromaSubsampling420BitDepth8());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MainStillChromaSubsampling444BitDepth8(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MainStillChromaSubsampling444BitDepth8());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MainStillChromaSubsampling444BitDepth16(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().MainStillChromaSubsampling444BitDepth16());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IImageEncodingProperties> : produce_base<D, winrt::Windows::Media::MediaProperties::IImageEncodingProperties>
    {
        int32_t __stdcall put_Width(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Width(value);
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
        int32_t __stdcall put_Height(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Height(value);
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
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IImageEncodingProperties2> : produce_base<D, winrt::Windows::Media::MediaProperties::IImageEncodingProperties2>
    {
        int32_t __stdcall Copy(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::MediaProperties::ImageEncodingProperties>(this->shim().Copy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IImageEncodingPropertiesStatics> : produce_base<D, winrt::Windows::Media::MediaProperties::IImageEncodingPropertiesStatics>
    {
        int32_t __stdcall CreateJpeg(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::ImageEncodingProperties>(this->shim().CreateJpeg());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreatePng(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::ImageEncodingProperties>(this->shim().CreatePng());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateJpegXR(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::ImageEncodingProperties>(this->shim().CreateJpegXR());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IImageEncodingPropertiesStatics2> : produce_base<D, winrt::Windows::Media::MediaProperties::IImageEncodingPropertiesStatics2>
    {
        int32_t __stdcall CreateUncompressed(int32_t format, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::ImageEncodingProperties>(this->shim().CreateUncompressed(*reinterpret_cast<winrt::Windows::Media::MediaProperties::MediaPixelFormat const*>(&format)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateBmp(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::ImageEncodingProperties>(this->shim().CreateBmp());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IImageEncodingPropertiesStatics3> : produce_base<D, winrt::Windows::Media::MediaProperties::IImageEncodingPropertiesStatics3>
    {
        int32_t __stdcall CreateHeif(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::MediaProperties::ImageEncodingProperties>(this->shim().CreateHeif());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IMediaEncodingProfile> : produce_base<D, winrt::Windows::Media::MediaProperties::IMediaEncodingProfile>
    {
        int32_t __stdcall put_Audio(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Audio(*reinterpret_cast<winrt::Windows::Media::MediaProperties::AudioEncodingProperties const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Audio(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().Audio());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Video(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Video(*reinterpret_cast<winrt::Windows::Media::MediaProperties::VideoEncodingProperties const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Video(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::VideoEncodingProperties>(this->shim().Video());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Container(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Container(*reinterpret_cast<winrt::Windows::Media::MediaProperties::ContainerEncodingProperties const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Container(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::ContainerEncodingProperties>(this->shim().Container());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IMediaEncodingProfile2> : produce_base<D, winrt::Windows::Media::MediaProperties::IMediaEncodingProfile2>
    {
        int32_t __stdcall SetAudioTracks(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetAudioTracks(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Media::Core::AudioStreamDescriptor> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetAudioTracks(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Media::Core::AudioStreamDescriptor>>(this->shim().GetAudioTracks());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetVideoTracks(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetVideoTracks(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Media::Core::VideoStreamDescriptor> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetVideoTracks(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Media::Core::VideoStreamDescriptor>>(this->shim().GetVideoTracks());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IMediaEncodingProfile3> : produce_base<D, winrt::Windows::Media::MediaProperties::IMediaEncodingProfile3>
    {
        int32_t __stdcall SetTimedMetadataTracks(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetTimedMetadataTracks(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Media::Core::TimedMetadataStreamDescriptor> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetTimedMetadataTracks(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Media::Core::TimedMetadataStreamDescriptor>>(this->shim().GetTimedMetadataTracks());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics> : produce_base<D, winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics>
    {
        int32_t __stdcall CreateM4a(int32_t quality, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::MediaEncodingProfile>(this->shim().CreateM4a(*reinterpret_cast<winrt::Windows::Media::MediaProperties::AudioEncodingQuality const*>(&quality)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateMp3(int32_t quality, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::MediaEncodingProfile>(this->shim().CreateMp3(*reinterpret_cast<winrt::Windows::Media::MediaProperties::AudioEncodingQuality const*>(&quality)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWma(int32_t quality, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::MediaEncodingProfile>(this->shim().CreateWma(*reinterpret_cast<winrt::Windows::Media::MediaProperties::AudioEncodingQuality const*>(&quality)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateMp4(int32_t quality, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::MediaEncodingProfile>(this->shim().CreateMp4(*reinterpret_cast<winrt::Windows::Media::MediaProperties::VideoEncodingQuality const*>(&quality)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWmv(int32_t quality, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::MediaEncodingProfile>(this->shim().CreateWmv(*reinterpret_cast<winrt::Windows::Media::MediaProperties::VideoEncodingQuality const*>(&quality)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromFileAsync(void* file, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::MediaProperties::MediaEncodingProfile>>(this->shim().CreateFromFileAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromStreamAsync(void* stream, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::MediaProperties::MediaEncodingProfile>>(this->shim().CreateFromStreamAsync(*reinterpret_cast<winrt::Windows::Storage::Streams::IRandomAccessStream const*>(&stream)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics2> : produce_base<D, winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics2>
    {
        int32_t __stdcall CreateWav(int32_t quality, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::MediaEncodingProfile>(this->shim().CreateWav(*reinterpret_cast<winrt::Windows::Media::MediaProperties::AudioEncodingQuality const*>(&quality)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateAvi(int32_t quality, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::MediaEncodingProfile>(this->shim().CreateAvi(*reinterpret_cast<winrt::Windows::Media::MediaProperties::VideoEncodingQuality const*>(&quality)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics3> : produce_base<D, winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics3>
    {
        int32_t __stdcall CreateAlac(int32_t quality, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::MediaEncodingProfile>(this->shim().CreateAlac(*reinterpret_cast<winrt::Windows::Media::MediaProperties::AudioEncodingQuality const*>(&quality)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFlac(int32_t quality, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::MediaEncodingProfile>(this->shim().CreateFlac(*reinterpret_cast<winrt::Windows::Media::MediaProperties::AudioEncodingQuality const*>(&quality)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateHevc(int32_t quality, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::MediaEncodingProfile>(this->shim().CreateHevc(*reinterpret_cast<winrt::Windows::Media::MediaProperties::VideoEncodingQuality const*>(&quality)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics4> : produce_base<D, winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics4>
    {
        int32_t __stdcall CreateVp9(int32_t quality, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::MediaProperties::MediaEncodingProfile>(this->shim().CreateVp9(*reinterpret_cast<winrt::Windows::Media::MediaProperties::VideoEncodingQuality const*>(&quality)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateAv1(int32_t quality, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::MediaProperties::MediaEncodingProfile>(this->shim().CreateAv1(*reinterpret_cast<winrt::Windows::Media::MediaProperties::VideoEncodingQuality const*>(&quality)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IMediaEncodingProperties> : produce_base<D, winrt::Windows::Media::MediaProperties::IMediaEncodingProperties>
    {
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::MediaPropertySet>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Type(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Subtype(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Subtype(*reinterpret_cast<hstring const*>(&value));
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
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics> : produce_base<D, winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics>
    {
        int32_t __stdcall get_Aac(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Aac());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AacAdts(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AacAdts());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Ac3(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Ac3());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AmrNb(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AmrNb());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AmrWb(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AmrWb());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Argb32(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Argb32());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Asf(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Asf());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Avi(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Avi());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Bgra8(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Bgra8());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Bmp(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Bmp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Eac3(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Eac3());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Float(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Float());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Gif(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Gif());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_H263(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().H263());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_H264(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().H264());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_H264Es(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().H264Es());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Hevc(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Hevc());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HevcEs(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().HevcEs());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Iyuv(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Iyuv());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Jpeg(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Jpeg());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_JpegXr(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().JpegXr());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Mjpg(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Mjpg());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Mpeg(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Mpeg());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Mpeg1(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Mpeg1());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Mpeg2(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Mpeg2());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Mp3(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Mp3());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Mpeg4(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Mpeg4());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Nv12(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Nv12());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Pcm(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Pcm());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Png(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Png());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Rgb24(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Rgb24());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Rgb32(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Rgb32());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Tiff(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Tiff());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Wave(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Wave());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Wma8(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Wma8());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Wma9(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Wma9());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Wmv3(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Wmv3());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Wvc1(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Wvc1());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Yuy2(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Yuy2());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Yv12(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Yv12());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics2> : produce_base<D, winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics2>
    {
        int32_t __stdcall get_Vp9(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Vp9());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_L8(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().L8());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_L16(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().L16());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_D16(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().D16());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics3> : produce_base<D, winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics3>
    {
        int32_t __stdcall get_Alac(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Alac());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Flac(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Flac());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics4> : produce_base<D, winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics4>
    {
        int32_t __stdcall get_P010(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().P010());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics5> : produce_base<D, winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics5>
    {
        int32_t __stdcall get_Heif(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Heif());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics6> : produce_base<D, winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics6>
    {
        int32_t __stdcall get_Pgs(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Pgs());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Srt(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Srt());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Ssa(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Ssa());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_VobSub(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().VobSub());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics7> : produce_base<D, winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics7>
    {
        int32_t __stdcall get_Av1(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Av1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IMediaRatio> : produce_base<D, winrt::Windows::Media::MediaProperties::IMediaRatio>
    {
        int32_t __stdcall put_Numerator(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Numerator(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Numerator(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Numerator());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Denominator(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Denominator(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Denominator(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Denominator());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IMpeg2ProfileIdsStatics> : produce_base<D, winrt::Windows::Media::MediaProperties::IMpeg2ProfileIdsStatics>
    {
        int32_t __stdcall get_Simple(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Simple());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Main(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Main());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SignalNoiseRatioScalable(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().SignalNoiseRatioScalable());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SpatiallyScalable(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().SpatiallyScalable());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_High(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().High());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::ITimedMetadataEncodingProperties> : produce_base<D, winrt::Windows::Media::MediaProperties::ITimedMetadataEncodingProperties>
    {
        int32_t __stdcall SetFormatUserData(uint32_t __valueSize, uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetFormatUserData(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(value), reinterpret_cast<uint8_t const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetFormatUserData(uint32_t* __valueSize, uint8_t** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            this->shim().GetFormatUserData(detach_abi<uint8_t>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Copy(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::MediaProperties::TimedMetadataEncodingProperties>(this->shim().Copy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::ITimedMetadataEncodingPropertiesStatics> : produce_base<D, winrt::Windows::Media::MediaProperties::ITimedMetadataEncodingPropertiesStatics>
    {
        int32_t __stdcall CreatePgs(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::MediaProperties::TimedMetadataEncodingProperties>(this->shim().CreatePgs());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateSrt(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::MediaProperties::TimedMetadataEncodingProperties>(this->shim().CreateSrt());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateSsa(uint32_t __formatUserDataSize, uint8_t* formatUserData, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::MediaProperties::TimedMetadataEncodingProperties>(this->shim().CreateSsa(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(formatUserData), reinterpret_cast<uint8_t const *>(formatUserData) + __formatUserDataSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateVobSub(uint32_t __formatUserDataSize, uint8_t* formatUserData, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::MediaProperties::TimedMetadataEncodingProperties>(this->shim().CreateVobSub(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(formatUserData), reinterpret_cast<uint8_t const *>(formatUserData) + __formatUserDataSize)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IVideoEncodingProperties> : produce_base<D, winrt::Windows::Media::MediaProperties::IVideoEncodingProperties>
    {
        int32_t __stdcall put_Bitrate(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Bitrate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Bitrate(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Bitrate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Width(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Width(value);
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
        int32_t __stdcall put_Height(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Height(value);
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
        int32_t __stdcall get_FrameRate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::MediaRatio>(this->shim().FrameRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PixelAspectRatio(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::MediaRatio>(this->shim().PixelAspectRatio());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IVideoEncodingProperties2> : produce_base<D, winrt::Windows::Media::MediaProperties::IVideoEncodingProperties2>
    {
        int32_t __stdcall SetFormatUserData(uint32_t __valueSize, uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetFormatUserData(array_view<uint8_t const>(reinterpret_cast<uint8_t const *>(value), reinterpret_cast<uint8_t const *>(value) + __valueSize));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetFormatUserData(uint32_t* __valueSize, uint8_t** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            this->shim().GetFormatUserData(detach_abi<uint8_t>(__valueSize, value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ProfileId(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProfileId(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProfileId(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().ProfileId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IVideoEncodingProperties3> : produce_base<D, winrt::Windows::Media::MediaProperties::IVideoEncodingProperties3>
    {
        int32_t __stdcall get_StereoscopicVideoPackingMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::StereoscopicVideoPackingMode>(this->shim().StereoscopicVideoPackingMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IVideoEncodingProperties4> : produce_base<D, winrt::Windows::Media::MediaProperties::IVideoEncodingProperties4>
    {
        int32_t __stdcall get_SphericalVideoFrameFormat(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::SphericalVideoFrameFormat>(this->shim().SphericalVideoFrameFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IVideoEncodingProperties5> : produce_base<D, winrt::Windows::Media::MediaProperties::IVideoEncodingProperties5>
    {
        int32_t __stdcall Copy(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::MediaProperties::VideoEncodingProperties>(this->shim().Copy());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics> : produce_base<D, winrt::Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics>
    {
        int32_t __stdcall CreateH264(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::VideoEncodingProperties>(this->shim().CreateH264());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateMpeg2(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::VideoEncodingProperties>(this->shim().CreateMpeg2());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateUncompressed(void* subtype, uint32_t width, uint32_t height, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::VideoEncodingProperties>(this->shim().CreateUncompressed(*reinterpret_cast<hstring const*>(&subtype), width, height));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics2> : produce_base<D, winrt::Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics2>
    {
        int32_t __stdcall CreateHevc(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::VideoEncodingProperties>(this->shim().CreateHevc());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics3> : produce_base<D, winrt::Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics3>
    {
        int32_t __stdcall CreateVp9(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::MediaProperties::VideoEncodingProperties>(this->shim().CreateVp9());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateAv1(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::MediaProperties::VideoEncodingProperties>(this->shim().CreateAv1());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::MediaProperties::IVp9ProfileIdsStatics> : produce_base<D, winrt::Windows::Media::MediaProperties::IVp9ProfileIdsStatics>
    {
        int32_t __stdcall get_Profile0ChromaSubsampling420BitDepth8(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Profile0ChromaSubsampling420BitDepth8());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Profile2ChromaSubsampling420BitDepth10(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Profile2ChromaSubsampling420BitDepth10());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Profile2ChromaSubsampling420BitDepth12(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().Profile2ChromaSubsampling420BitDepth12());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Media::MediaProperties
{
    constexpr auto operator|(MediaMirroringOptions const left, MediaMirroringOptions const right) noexcept
    {
        return static_cast<MediaMirroringOptions>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(MediaMirroringOptions& left, MediaMirroringOptions const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(MediaMirroringOptions const left, MediaMirroringOptions const right) noexcept
    {
        return static_cast<MediaMirroringOptions>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(MediaMirroringOptions& left, MediaMirroringOptions const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(MediaMirroringOptions const value) noexcept
    {
        return static_cast<MediaMirroringOptions>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(MediaMirroringOptions const left, MediaMirroringOptions const right) noexcept
    {
        return static_cast<MediaMirroringOptions>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(MediaMirroringOptions& left, MediaMirroringOptions const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline AudioEncodingProperties::AudioEncodingProperties() :
        AudioEncodingProperties(impl::call_factory_cast<AudioEncodingProperties(*)(winrt::Windows::Foundation::IActivationFactory const&), AudioEncodingProperties>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<AudioEncodingProperties>(); }))
    {
    }
    inline auto AudioEncodingProperties::CreateAac(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate)
    {
        return impl::call_factory<AudioEncodingProperties, IAudioEncodingPropertiesStatics>([&](IAudioEncodingPropertiesStatics const& f) { return f.CreateAac(sampleRate, channelCount, bitrate); });
    }
    inline auto AudioEncodingProperties::CreateAacAdts(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate)
    {
        return impl::call_factory<AudioEncodingProperties, IAudioEncodingPropertiesStatics>([&](IAudioEncodingPropertiesStatics const& f) { return f.CreateAacAdts(sampleRate, channelCount, bitrate); });
    }
    inline auto AudioEncodingProperties::CreateMp3(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate)
    {
        return impl::call_factory<AudioEncodingProperties, IAudioEncodingPropertiesStatics>([&](IAudioEncodingPropertiesStatics const& f) { return f.CreateMp3(sampleRate, channelCount, bitrate); });
    }
    inline auto AudioEncodingProperties::CreatePcm(uint32_t sampleRate, uint32_t channelCount, uint32_t bitsPerSample)
    {
        return impl::call_factory<AudioEncodingProperties, IAudioEncodingPropertiesStatics>([&](IAudioEncodingPropertiesStatics const& f) { return f.CreatePcm(sampleRate, channelCount, bitsPerSample); });
    }
    inline auto AudioEncodingProperties::CreateWma(uint32_t sampleRate, uint32_t channelCount, uint32_t bitrate)
    {
        return impl::call_factory<AudioEncodingProperties, IAudioEncodingPropertiesStatics>([&](IAudioEncodingPropertiesStatics const& f) { return f.CreateWma(sampleRate, channelCount, bitrate); });
    }
    inline auto AudioEncodingProperties::CreateAlac(uint32_t sampleRate, uint32_t channelCount, uint32_t bitsPerSample)
    {
        return impl::call_factory<AudioEncodingProperties, IAudioEncodingPropertiesStatics2>([&](IAudioEncodingPropertiesStatics2 const& f) { return f.CreateAlac(sampleRate, channelCount, bitsPerSample); });
    }
    inline auto AudioEncodingProperties::CreateFlac(uint32_t sampleRate, uint32_t channelCount, uint32_t bitsPerSample)
    {
        return impl::call_factory<AudioEncodingProperties, IAudioEncodingPropertiesStatics2>([&](IAudioEncodingPropertiesStatics2 const& f) { return f.CreateFlac(sampleRate, channelCount, bitsPerSample); });
    }
    inline auto Av1ProfileIds::MainChromaSubsampling420BitDepth8()
    {
        return impl::call_factory_cast<int32_t(*)(IAv1ProfileIdsStatics const&), Av1ProfileIds, IAv1ProfileIdsStatics>([](IAv1ProfileIdsStatics const& f) { return f.MainChromaSubsampling420BitDepth8(); });
    }
    inline auto Av1ProfileIds::MainChromaSubsampling420BitDepth10()
    {
        return impl::call_factory_cast<int32_t(*)(IAv1ProfileIdsStatics const&), Av1ProfileIds, IAv1ProfileIdsStatics>([](IAv1ProfileIdsStatics const& f) { return f.MainChromaSubsampling420BitDepth10(); });
    }
    inline auto Av1ProfileIds::MainChromaSubsampling400BitDepth8()
    {
        return impl::call_factory_cast<int32_t(*)(IAv1ProfileIdsStatics const&), Av1ProfileIds, IAv1ProfileIdsStatics>([](IAv1ProfileIdsStatics const& f) { return f.MainChromaSubsampling400BitDepth8(); });
    }
    inline auto Av1ProfileIds::MainChromaSubsampling400BitDepth10()
    {
        return impl::call_factory_cast<int32_t(*)(IAv1ProfileIdsStatics const&), Av1ProfileIds, IAv1ProfileIdsStatics>([](IAv1ProfileIdsStatics const& f) { return f.MainChromaSubsampling400BitDepth10(); });
    }
    inline auto Av1ProfileIds::HighChromaSubsampling444BitDepth8()
    {
        return impl::call_factory_cast<int32_t(*)(IAv1ProfileIdsStatics const&), Av1ProfileIds, IAv1ProfileIdsStatics>([](IAv1ProfileIdsStatics const& f) { return f.HighChromaSubsampling444BitDepth8(); });
    }
    inline auto Av1ProfileIds::HighChromaSubsampling444BitDepth10()
    {
        return impl::call_factory_cast<int32_t(*)(IAv1ProfileIdsStatics const&), Av1ProfileIds, IAv1ProfileIdsStatics>([](IAv1ProfileIdsStatics const& f) { return f.HighChromaSubsampling444BitDepth10(); });
    }
    inline auto Av1ProfileIds::ProfessionalChromaSubsampling420BitDepth12()
    {
        return impl::call_factory_cast<int32_t(*)(IAv1ProfileIdsStatics const&), Av1ProfileIds, IAv1ProfileIdsStatics>([](IAv1ProfileIdsStatics const& f) { return f.ProfessionalChromaSubsampling420BitDepth12(); });
    }
    inline auto Av1ProfileIds::ProfessionalChromaSubsampling400BitDepth12()
    {
        return impl::call_factory_cast<int32_t(*)(IAv1ProfileIdsStatics const&), Av1ProfileIds, IAv1ProfileIdsStatics>([](IAv1ProfileIdsStatics const& f) { return f.ProfessionalChromaSubsampling400BitDepth12(); });
    }
    inline auto Av1ProfileIds::ProfessionalChromaSubsampling444BitDepth12()
    {
        return impl::call_factory_cast<int32_t(*)(IAv1ProfileIdsStatics const&), Av1ProfileIds, IAv1ProfileIdsStatics>([](IAv1ProfileIdsStatics const& f) { return f.ProfessionalChromaSubsampling444BitDepth12(); });
    }
    inline auto Av1ProfileIds::ProfessionalChromaSubsampling422BitDepth8()
    {
        return impl::call_factory_cast<int32_t(*)(IAv1ProfileIdsStatics const&), Av1ProfileIds, IAv1ProfileIdsStatics>([](IAv1ProfileIdsStatics const& f) { return f.ProfessionalChromaSubsampling422BitDepth8(); });
    }
    inline auto Av1ProfileIds::ProfessionalChromaSubsampling422BitDepth10()
    {
        return impl::call_factory_cast<int32_t(*)(IAv1ProfileIdsStatics const&), Av1ProfileIds, IAv1ProfileIdsStatics>([](IAv1ProfileIdsStatics const& f) { return f.ProfessionalChromaSubsampling422BitDepth10(); });
    }
    inline auto Av1ProfileIds::ProfessionalChromaSubsampling422BitDepth12()
    {
        return impl::call_factory_cast<int32_t(*)(IAv1ProfileIdsStatics const&), Av1ProfileIds, IAv1ProfileIdsStatics>([](IAv1ProfileIdsStatics const& f) { return f.ProfessionalChromaSubsampling422BitDepth12(); });
    }
    inline ContainerEncodingProperties::ContainerEncodingProperties() :
        ContainerEncodingProperties(impl::call_factory_cast<ContainerEncodingProperties(*)(winrt::Windows::Foundation::IActivationFactory const&), ContainerEncodingProperties>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ContainerEncodingProperties>(); }))
    {
    }
    inline auto H264ProfileIds::ConstrainedBaseline()
    {
        return impl::call_factory_cast<int32_t(*)(IH264ProfileIdsStatics const&), H264ProfileIds, IH264ProfileIdsStatics>([](IH264ProfileIdsStatics const& f) { return f.ConstrainedBaseline(); });
    }
    inline auto H264ProfileIds::Baseline()
    {
        return impl::call_factory_cast<int32_t(*)(IH264ProfileIdsStatics const&), H264ProfileIds, IH264ProfileIdsStatics>([](IH264ProfileIdsStatics const& f) { return f.Baseline(); });
    }
    inline auto H264ProfileIds::Extended()
    {
        return impl::call_factory_cast<int32_t(*)(IH264ProfileIdsStatics const&), H264ProfileIds, IH264ProfileIdsStatics>([](IH264ProfileIdsStatics const& f) { return f.Extended(); });
    }
    inline auto H264ProfileIds::Main()
    {
        return impl::call_factory_cast<int32_t(*)(IH264ProfileIdsStatics const&), H264ProfileIds, IH264ProfileIdsStatics>([](IH264ProfileIdsStatics const& f) { return f.Main(); });
    }
    inline auto H264ProfileIds::High()
    {
        return impl::call_factory_cast<int32_t(*)(IH264ProfileIdsStatics const&), H264ProfileIds, IH264ProfileIdsStatics>([](IH264ProfileIdsStatics const& f) { return f.High(); });
    }
    inline auto H264ProfileIds::High10()
    {
        return impl::call_factory_cast<int32_t(*)(IH264ProfileIdsStatics const&), H264ProfileIds, IH264ProfileIdsStatics>([](IH264ProfileIdsStatics const& f) { return f.High10(); });
    }
    inline auto H264ProfileIds::High422()
    {
        return impl::call_factory_cast<int32_t(*)(IH264ProfileIdsStatics const&), H264ProfileIds, IH264ProfileIdsStatics>([](IH264ProfileIdsStatics const& f) { return f.High422(); });
    }
    inline auto H264ProfileIds::High444()
    {
        return impl::call_factory_cast<int32_t(*)(IH264ProfileIdsStatics const&), H264ProfileIds, IH264ProfileIdsStatics>([](IH264ProfileIdsStatics const& f) { return f.High444(); });
    }
    inline auto H264ProfileIds::StereoHigh()
    {
        return impl::call_factory_cast<int32_t(*)(IH264ProfileIdsStatics const&), H264ProfileIds, IH264ProfileIdsStatics>([](IH264ProfileIdsStatics const& f) { return f.StereoHigh(); });
    }
    inline auto H264ProfileIds::MultiviewHigh()
    {
        return impl::call_factory_cast<int32_t(*)(IH264ProfileIdsStatics const&), H264ProfileIds, IH264ProfileIdsStatics>([](IH264ProfileIdsStatics const& f) { return f.MultiviewHigh(); });
    }
    inline auto HevcProfileIds::MainChromaSubsampling420BitDepth8()
    {
        return impl::call_factory_cast<int32_t(*)(IHevcProfileIdsStatics const&), HevcProfileIds, IHevcProfileIdsStatics>([](IHevcProfileIdsStatics const& f) { return f.MainChromaSubsampling420BitDepth8(); });
    }
    inline auto HevcProfileIds::MainChromaSubsampling420BitDepth10()
    {
        return impl::call_factory_cast<int32_t(*)(IHevcProfileIdsStatics const&), HevcProfileIds, IHevcProfileIdsStatics>([](IHevcProfileIdsStatics const& f) { return f.MainChromaSubsampling420BitDepth10(); });
    }
    inline auto HevcProfileIds::MainChromaSubsampling420BitDepth12()
    {
        return impl::call_factory_cast<int32_t(*)(IHevcProfileIdsStatics const&), HevcProfileIds, IHevcProfileIdsStatics>([](IHevcProfileIdsStatics const& f) { return f.MainChromaSubsampling420BitDepth12(); });
    }
    inline auto HevcProfileIds::MainChromaSubsampling422BitDepth10()
    {
        return impl::call_factory_cast<int32_t(*)(IHevcProfileIdsStatics const&), HevcProfileIds, IHevcProfileIdsStatics>([](IHevcProfileIdsStatics const& f) { return f.MainChromaSubsampling422BitDepth10(); });
    }
    inline auto HevcProfileIds::MainChromaSubsampling422BitDepth12()
    {
        return impl::call_factory_cast<int32_t(*)(IHevcProfileIdsStatics const&), HevcProfileIds, IHevcProfileIdsStatics>([](IHevcProfileIdsStatics const& f) { return f.MainChromaSubsampling422BitDepth12(); });
    }
    inline auto HevcProfileIds::MainChromaSubsampling444BitDepth8()
    {
        return impl::call_factory_cast<int32_t(*)(IHevcProfileIdsStatics const&), HevcProfileIds, IHevcProfileIdsStatics>([](IHevcProfileIdsStatics const& f) { return f.MainChromaSubsampling444BitDepth8(); });
    }
    inline auto HevcProfileIds::MainChromaSubsampling444BitDepth10()
    {
        return impl::call_factory_cast<int32_t(*)(IHevcProfileIdsStatics const&), HevcProfileIds, IHevcProfileIdsStatics>([](IHevcProfileIdsStatics const& f) { return f.MainChromaSubsampling444BitDepth10(); });
    }
    inline auto HevcProfileIds::MainChromaSubsampling444BitDepth12()
    {
        return impl::call_factory_cast<int32_t(*)(IHevcProfileIdsStatics const&), HevcProfileIds, IHevcProfileIdsStatics>([](IHevcProfileIdsStatics const& f) { return f.MainChromaSubsampling444BitDepth12(); });
    }
    inline auto HevcProfileIds::MonochromeBitDepth12()
    {
        return impl::call_factory_cast<int32_t(*)(IHevcProfileIdsStatics const&), HevcProfileIds, IHevcProfileIdsStatics>([](IHevcProfileIdsStatics const& f) { return f.MonochromeBitDepth12(); });
    }
    inline auto HevcProfileIds::MonochromeBitDepth16()
    {
        return impl::call_factory_cast<int32_t(*)(IHevcProfileIdsStatics const&), HevcProfileIds, IHevcProfileIdsStatics>([](IHevcProfileIdsStatics const& f) { return f.MonochromeBitDepth16(); });
    }
    inline auto HevcProfileIds::MainIntraChromaSubsampling420BitDepth8()
    {
        return impl::call_factory_cast<int32_t(*)(IHevcProfileIdsStatics const&), HevcProfileIds, IHevcProfileIdsStatics>([](IHevcProfileIdsStatics const& f) { return f.MainIntraChromaSubsampling420BitDepth8(); });
    }
    inline auto HevcProfileIds::MainIntraChromaSubsampling420BitDepth10()
    {
        return impl::call_factory_cast<int32_t(*)(IHevcProfileIdsStatics const&), HevcProfileIds, IHevcProfileIdsStatics>([](IHevcProfileIdsStatics const& f) { return f.MainIntraChromaSubsampling420BitDepth10(); });
    }
    inline auto HevcProfileIds::MainIntraChromaSubsampling420BitDepth12()
    {
        return impl::call_factory_cast<int32_t(*)(IHevcProfileIdsStatics const&), HevcProfileIds, IHevcProfileIdsStatics>([](IHevcProfileIdsStatics const& f) { return f.MainIntraChromaSubsampling420BitDepth12(); });
    }
    inline auto HevcProfileIds::MainIntraChromaSubsampling422BitDepth10()
    {
        return impl::call_factory_cast<int32_t(*)(IHevcProfileIdsStatics const&), HevcProfileIds, IHevcProfileIdsStatics>([](IHevcProfileIdsStatics const& f) { return f.MainIntraChromaSubsampling422BitDepth10(); });
    }
    inline auto HevcProfileIds::MainIntraChromaSubsampling422BitDepth12()
    {
        return impl::call_factory_cast<int32_t(*)(IHevcProfileIdsStatics const&), HevcProfileIds, IHevcProfileIdsStatics>([](IHevcProfileIdsStatics const& f) { return f.MainIntraChromaSubsampling422BitDepth12(); });
    }
    inline auto HevcProfileIds::MainIntraChromaSubsampling444BitDepth8()
    {
        return impl::call_factory_cast<int32_t(*)(IHevcProfileIdsStatics const&), HevcProfileIds, IHevcProfileIdsStatics>([](IHevcProfileIdsStatics const& f) { return f.MainIntraChromaSubsampling444BitDepth8(); });
    }
    inline auto HevcProfileIds::MainIntraChromaSubsampling444BitDepth10()
    {
        return impl::call_factory_cast<int32_t(*)(IHevcProfileIdsStatics const&), HevcProfileIds, IHevcProfileIdsStatics>([](IHevcProfileIdsStatics const& f) { return f.MainIntraChromaSubsampling444BitDepth10(); });
    }
    inline auto HevcProfileIds::MainIntraChromaSubsampling444BitDepth12()
    {
        return impl::call_factory_cast<int32_t(*)(IHevcProfileIdsStatics const&), HevcProfileIds, IHevcProfileIdsStatics>([](IHevcProfileIdsStatics const& f) { return f.MainIntraChromaSubsampling444BitDepth12(); });
    }
    inline auto HevcProfileIds::MainIntraChromaSubsampling444BitDepth16()
    {
        return impl::call_factory_cast<int32_t(*)(IHevcProfileIdsStatics const&), HevcProfileIds, IHevcProfileIdsStatics>([](IHevcProfileIdsStatics const& f) { return f.MainIntraChromaSubsampling444BitDepth16(); });
    }
    inline auto HevcProfileIds::MainStillChromaSubsampling420BitDepth8()
    {
        return impl::call_factory_cast<int32_t(*)(IHevcProfileIdsStatics const&), HevcProfileIds, IHevcProfileIdsStatics>([](IHevcProfileIdsStatics const& f) { return f.MainStillChromaSubsampling420BitDepth8(); });
    }
    inline auto HevcProfileIds::MainStillChromaSubsampling444BitDepth8()
    {
        return impl::call_factory_cast<int32_t(*)(IHevcProfileIdsStatics const&), HevcProfileIds, IHevcProfileIdsStatics>([](IHevcProfileIdsStatics const& f) { return f.MainStillChromaSubsampling444BitDepth8(); });
    }
    inline auto HevcProfileIds::MainStillChromaSubsampling444BitDepth16()
    {
        return impl::call_factory_cast<int32_t(*)(IHevcProfileIdsStatics const&), HevcProfileIds, IHevcProfileIdsStatics>([](IHevcProfileIdsStatics const& f) { return f.MainStillChromaSubsampling444BitDepth16(); });
    }
    inline ImageEncodingProperties::ImageEncodingProperties() :
        ImageEncodingProperties(impl::call_factory_cast<ImageEncodingProperties(*)(winrt::Windows::Foundation::IActivationFactory const&), ImageEncodingProperties>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<ImageEncodingProperties>(); }))
    {
    }
    inline auto ImageEncodingProperties::CreateJpeg()
    {
        return impl::call_factory_cast<winrt::Windows::Media::MediaProperties::ImageEncodingProperties(*)(IImageEncodingPropertiesStatics const&), ImageEncodingProperties, IImageEncodingPropertiesStatics>([](IImageEncodingPropertiesStatics const& f) { return f.CreateJpeg(); });
    }
    inline auto ImageEncodingProperties::CreatePng()
    {
        return impl::call_factory_cast<winrt::Windows::Media::MediaProperties::ImageEncodingProperties(*)(IImageEncodingPropertiesStatics const&), ImageEncodingProperties, IImageEncodingPropertiesStatics>([](IImageEncodingPropertiesStatics const& f) { return f.CreatePng(); });
    }
    inline auto ImageEncodingProperties::CreateJpegXR()
    {
        return impl::call_factory_cast<winrt::Windows::Media::MediaProperties::ImageEncodingProperties(*)(IImageEncodingPropertiesStatics const&), ImageEncodingProperties, IImageEncodingPropertiesStatics>([](IImageEncodingPropertiesStatics const& f) { return f.CreateJpegXR(); });
    }
    inline auto ImageEncodingProperties::CreateUncompressed(winrt::Windows::Media::MediaProperties::MediaPixelFormat const& format)
    {
        return impl::call_factory<ImageEncodingProperties, IImageEncodingPropertiesStatics2>([&](IImageEncodingPropertiesStatics2 const& f) { return f.CreateUncompressed(format); });
    }
    inline auto ImageEncodingProperties::CreateBmp()
    {
        return impl::call_factory_cast<winrt::Windows::Media::MediaProperties::ImageEncodingProperties(*)(IImageEncodingPropertiesStatics2 const&), ImageEncodingProperties, IImageEncodingPropertiesStatics2>([](IImageEncodingPropertiesStatics2 const& f) { return f.CreateBmp(); });
    }
    inline auto ImageEncodingProperties::CreateHeif()
    {
        return impl::call_factory_cast<winrt::Windows::Media::MediaProperties::ImageEncodingProperties(*)(IImageEncodingPropertiesStatics3 const&), ImageEncodingProperties, IImageEncodingPropertiesStatics3>([](IImageEncodingPropertiesStatics3 const& f) { return f.CreateHeif(); });
    }
    inline MediaEncodingProfile::MediaEncodingProfile() :
        MediaEncodingProfile(impl::call_factory_cast<MediaEncodingProfile(*)(winrt::Windows::Foundation::IActivationFactory const&), MediaEncodingProfile>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<MediaEncodingProfile>(); }))
    {
    }
    inline auto MediaEncodingProfile::CreateM4a(winrt::Windows::Media::MediaProperties::AudioEncodingQuality const& quality)
    {
        return impl::call_factory<MediaEncodingProfile, IMediaEncodingProfileStatics>([&](IMediaEncodingProfileStatics const& f) { return f.CreateM4a(quality); });
    }
    inline auto MediaEncodingProfile::CreateMp3(winrt::Windows::Media::MediaProperties::AudioEncodingQuality const& quality)
    {
        return impl::call_factory<MediaEncodingProfile, IMediaEncodingProfileStatics>([&](IMediaEncodingProfileStatics const& f) { return f.CreateMp3(quality); });
    }
    inline auto MediaEncodingProfile::CreateWma(winrt::Windows::Media::MediaProperties::AudioEncodingQuality const& quality)
    {
        return impl::call_factory<MediaEncodingProfile, IMediaEncodingProfileStatics>([&](IMediaEncodingProfileStatics const& f) { return f.CreateWma(quality); });
    }
    inline auto MediaEncodingProfile::CreateMp4(winrt::Windows::Media::MediaProperties::VideoEncodingQuality const& quality)
    {
        return impl::call_factory<MediaEncodingProfile, IMediaEncodingProfileStatics>([&](IMediaEncodingProfileStatics const& f) { return f.CreateMp4(quality); });
    }
    inline auto MediaEncodingProfile::CreateWmv(winrt::Windows::Media::MediaProperties::VideoEncodingQuality const& quality)
    {
        return impl::call_factory<MediaEncodingProfile, IMediaEncodingProfileStatics>([&](IMediaEncodingProfileStatics const& f) { return f.CreateWmv(quality); });
    }
    inline auto MediaEncodingProfile::CreateFromFileAsync(winrt::Windows::Storage::IStorageFile const& file)
    {
        return impl::call_factory<MediaEncodingProfile, IMediaEncodingProfileStatics>([&](IMediaEncodingProfileStatics const& f) { return f.CreateFromFileAsync(file); });
    }
    inline auto MediaEncodingProfile::CreateFromStreamAsync(winrt::Windows::Storage::Streams::IRandomAccessStream const& stream)
    {
        return impl::call_factory<MediaEncodingProfile, IMediaEncodingProfileStatics>([&](IMediaEncodingProfileStatics const& f) { return f.CreateFromStreamAsync(stream); });
    }
    inline auto MediaEncodingProfile::CreateWav(winrt::Windows::Media::MediaProperties::AudioEncodingQuality const& quality)
    {
        return impl::call_factory<MediaEncodingProfile, IMediaEncodingProfileStatics2>([&](IMediaEncodingProfileStatics2 const& f) { return f.CreateWav(quality); });
    }
    inline auto MediaEncodingProfile::CreateAvi(winrt::Windows::Media::MediaProperties::VideoEncodingQuality const& quality)
    {
        return impl::call_factory<MediaEncodingProfile, IMediaEncodingProfileStatics2>([&](IMediaEncodingProfileStatics2 const& f) { return f.CreateAvi(quality); });
    }
    inline auto MediaEncodingProfile::CreateAlac(winrt::Windows::Media::MediaProperties::AudioEncodingQuality const& quality)
    {
        return impl::call_factory<MediaEncodingProfile, IMediaEncodingProfileStatics3>([&](IMediaEncodingProfileStatics3 const& f) { return f.CreateAlac(quality); });
    }
    inline auto MediaEncodingProfile::CreateFlac(winrt::Windows::Media::MediaProperties::AudioEncodingQuality const& quality)
    {
        return impl::call_factory<MediaEncodingProfile, IMediaEncodingProfileStatics3>([&](IMediaEncodingProfileStatics3 const& f) { return f.CreateFlac(quality); });
    }
    inline auto MediaEncodingProfile::CreateHevc(winrt::Windows::Media::MediaProperties::VideoEncodingQuality const& quality)
    {
        return impl::call_factory<MediaEncodingProfile, IMediaEncodingProfileStatics3>([&](IMediaEncodingProfileStatics3 const& f) { return f.CreateHevc(quality); });
    }
    inline auto MediaEncodingProfile::CreateVp9(winrt::Windows::Media::MediaProperties::VideoEncodingQuality const& quality)
    {
        return impl::call_factory<MediaEncodingProfile, IMediaEncodingProfileStatics4>([&](IMediaEncodingProfileStatics4 const& f) { return f.CreateVp9(quality); });
    }
    inline auto MediaEncodingProfile::CreateAv1(winrt::Windows::Media::MediaProperties::VideoEncodingQuality const& quality)
    {
        return impl::call_factory<MediaEncodingProfile, IMediaEncodingProfileStatics4>([&](IMediaEncodingProfileStatics4 const& f) { return f.CreateAv1(quality); });
    }
    inline auto MediaEncodingSubtypes::Aac()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Aac(); });
    }
    inline auto MediaEncodingSubtypes::AacAdts()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.AacAdts(); });
    }
    inline auto MediaEncodingSubtypes::Ac3()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Ac3(); });
    }
    inline auto MediaEncodingSubtypes::AmrNb()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.AmrNb(); });
    }
    inline auto MediaEncodingSubtypes::AmrWb()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.AmrWb(); });
    }
    inline auto MediaEncodingSubtypes::Argb32()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Argb32(); });
    }
    inline auto MediaEncodingSubtypes::Asf()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Asf(); });
    }
    inline auto MediaEncodingSubtypes::Avi()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Avi(); });
    }
    inline auto MediaEncodingSubtypes::Bgra8()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Bgra8(); });
    }
    inline auto MediaEncodingSubtypes::Bmp()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Bmp(); });
    }
    inline auto MediaEncodingSubtypes::Eac3()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Eac3(); });
    }
    inline auto MediaEncodingSubtypes::Float()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Float(); });
    }
    inline auto MediaEncodingSubtypes::Gif()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Gif(); });
    }
    inline auto MediaEncodingSubtypes::H263()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.H263(); });
    }
    inline auto MediaEncodingSubtypes::H264()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.H264(); });
    }
    inline auto MediaEncodingSubtypes::H264Es()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.H264Es(); });
    }
    inline auto MediaEncodingSubtypes::Hevc()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Hevc(); });
    }
    inline auto MediaEncodingSubtypes::HevcEs()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.HevcEs(); });
    }
    inline auto MediaEncodingSubtypes::Iyuv()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Iyuv(); });
    }
    inline auto MediaEncodingSubtypes::Jpeg()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Jpeg(); });
    }
    inline auto MediaEncodingSubtypes::JpegXr()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.JpegXr(); });
    }
    inline auto MediaEncodingSubtypes::Mjpg()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Mjpg(); });
    }
    inline auto MediaEncodingSubtypes::Mpeg()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Mpeg(); });
    }
    inline auto MediaEncodingSubtypes::Mpeg1()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Mpeg1(); });
    }
    inline auto MediaEncodingSubtypes::Mpeg2()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Mpeg2(); });
    }
    inline auto MediaEncodingSubtypes::Mp3()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Mp3(); });
    }
    inline auto MediaEncodingSubtypes::Mpeg4()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Mpeg4(); });
    }
    inline auto MediaEncodingSubtypes::Nv12()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Nv12(); });
    }
    inline auto MediaEncodingSubtypes::Pcm()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Pcm(); });
    }
    inline auto MediaEncodingSubtypes::Png()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Png(); });
    }
    inline auto MediaEncodingSubtypes::Rgb24()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Rgb24(); });
    }
    inline auto MediaEncodingSubtypes::Rgb32()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Rgb32(); });
    }
    inline auto MediaEncodingSubtypes::Tiff()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Tiff(); });
    }
    inline auto MediaEncodingSubtypes::Wave()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Wave(); });
    }
    inline auto MediaEncodingSubtypes::Wma8()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Wma8(); });
    }
    inline auto MediaEncodingSubtypes::Wma9()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Wma9(); });
    }
    inline auto MediaEncodingSubtypes::Wmv3()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Wmv3(); });
    }
    inline auto MediaEncodingSubtypes::Wvc1()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Wvc1(); });
    }
    inline auto MediaEncodingSubtypes::Yuy2()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Yuy2(); });
    }
    inline auto MediaEncodingSubtypes::Yv12()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics>([](IMediaEncodingSubtypesStatics const& f) { return f.Yv12(); });
    }
    inline auto MediaEncodingSubtypes::Vp9()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics2 const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics2>([](IMediaEncodingSubtypesStatics2 const& f) { return f.Vp9(); });
    }
    inline auto MediaEncodingSubtypes::L8()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics2 const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics2>([](IMediaEncodingSubtypesStatics2 const& f) { return f.L8(); });
    }
    inline auto MediaEncodingSubtypes::L16()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics2 const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics2>([](IMediaEncodingSubtypesStatics2 const& f) { return f.L16(); });
    }
    inline auto MediaEncodingSubtypes::D16()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics2 const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics2>([](IMediaEncodingSubtypesStatics2 const& f) { return f.D16(); });
    }
    inline auto MediaEncodingSubtypes::Alac()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics3 const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics3>([](IMediaEncodingSubtypesStatics3 const& f) { return f.Alac(); });
    }
    inline auto MediaEncodingSubtypes::Flac()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics3 const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics3>([](IMediaEncodingSubtypesStatics3 const& f) { return f.Flac(); });
    }
    inline auto MediaEncodingSubtypes::P010()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics4 const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics4>([](IMediaEncodingSubtypesStatics4 const& f) { return f.P010(); });
    }
    inline auto MediaEncodingSubtypes::Heif()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics5 const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics5>([](IMediaEncodingSubtypesStatics5 const& f) { return f.Heif(); });
    }
    inline auto MediaEncodingSubtypes::Pgs()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics6 const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics6>([](IMediaEncodingSubtypesStatics6 const& f) { return f.Pgs(); });
    }
    inline auto MediaEncodingSubtypes::Srt()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics6 const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics6>([](IMediaEncodingSubtypesStatics6 const& f) { return f.Srt(); });
    }
    inline auto MediaEncodingSubtypes::Ssa()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics6 const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics6>([](IMediaEncodingSubtypesStatics6 const& f) { return f.Ssa(); });
    }
    inline auto MediaEncodingSubtypes::VobSub()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics6 const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics6>([](IMediaEncodingSubtypesStatics6 const& f) { return f.VobSub(); });
    }
    inline auto MediaEncodingSubtypes::Av1()
    {
        return impl::call_factory_cast<hstring(*)(IMediaEncodingSubtypesStatics7 const&), MediaEncodingSubtypes, IMediaEncodingSubtypesStatics7>([](IMediaEncodingSubtypesStatics7 const& f) { return f.Av1(); });
    }
    inline MediaPropertySet::MediaPropertySet() :
        MediaPropertySet(impl::call_factory_cast<MediaPropertySet(*)(winrt::Windows::Foundation::IActivationFactory const&), MediaPropertySet>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<MediaPropertySet>(); }))
    {
    }
    inline auto Mpeg2ProfileIds::Simple()
    {
        return impl::call_factory_cast<int32_t(*)(IMpeg2ProfileIdsStatics const&), Mpeg2ProfileIds, IMpeg2ProfileIdsStatics>([](IMpeg2ProfileIdsStatics const& f) { return f.Simple(); });
    }
    inline auto Mpeg2ProfileIds::Main()
    {
        return impl::call_factory_cast<int32_t(*)(IMpeg2ProfileIdsStatics const&), Mpeg2ProfileIds, IMpeg2ProfileIdsStatics>([](IMpeg2ProfileIdsStatics const& f) { return f.Main(); });
    }
    inline auto Mpeg2ProfileIds::SignalNoiseRatioScalable()
    {
        return impl::call_factory_cast<int32_t(*)(IMpeg2ProfileIdsStatics const&), Mpeg2ProfileIds, IMpeg2ProfileIdsStatics>([](IMpeg2ProfileIdsStatics const& f) { return f.SignalNoiseRatioScalable(); });
    }
    inline auto Mpeg2ProfileIds::SpatiallyScalable()
    {
        return impl::call_factory_cast<int32_t(*)(IMpeg2ProfileIdsStatics const&), Mpeg2ProfileIds, IMpeg2ProfileIdsStatics>([](IMpeg2ProfileIdsStatics const& f) { return f.SpatiallyScalable(); });
    }
    inline auto Mpeg2ProfileIds::High()
    {
        return impl::call_factory_cast<int32_t(*)(IMpeg2ProfileIdsStatics const&), Mpeg2ProfileIds, IMpeg2ProfileIdsStatics>([](IMpeg2ProfileIdsStatics const& f) { return f.High(); });
    }
    inline TimedMetadataEncodingProperties::TimedMetadataEncodingProperties() :
        TimedMetadataEncodingProperties(impl::call_factory_cast<TimedMetadataEncodingProperties(*)(winrt::Windows::Foundation::IActivationFactory const&), TimedMetadataEncodingProperties>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<TimedMetadataEncodingProperties>(); }))
    {
    }
    inline auto TimedMetadataEncodingProperties::CreatePgs()
    {
        return impl::call_factory_cast<winrt::Windows::Media::MediaProperties::TimedMetadataEncodingProperties(*)(ITimedMetadataEncodingPropertiesStatics const&), TimedMetadataEncodingProperties, ITimedMetadataEncodingPropertiesStatics>([](ITimedMetadataEncodingPropertiesStatics const& f) { return f.CreatePgs(); });
    }
    inline auto TimedMetadataEncodingProperties::CreateSrt()
    {
        return impl::call_factory_cast<winrt::Windows::Media::MediaProperties::TimedMetadataEncodingProperties(*)(ITimedMetadataEncodingPropertiesStatics const&), TimedMetadataEncodingProperties, ITimedMetadataEncodingPropertiesStatics>([](ITimedMetadataEncodingPropertiesStatics const& f) { return f.CreateSrt(); });
    }
    inline auto TimedMetadataEncodingProperties::CreateSsa(array_view<uint8_t const> formatUserData)
    {
        return impl::call_factory<TimedMetadataEncodingProperties, ITimedMetadataEncodingPropertiesStatics>([&](ITimedMetadataEncodingPropertiesStatics const& f) { return f.CreateSsa(formatUserData); });
    }
    inline auto TimedMetadataEncodingProperties::CreateVobSub(array_view<uint8_t const> formatUserData)
    {
        return impl::call_factory<TimedMetadataEncodingProperties, ITimedMetadataEncodingPropertiesStatics>([&](ITimedMetadataEncodingPropertiesStatics const& f) { return f.CreateVobSub(formatUserData); });
    }
    inline VideoEncodingProperties::VideoEncodingProperties() :
        VideoEncodingProperties(impl::call_factory_cast<VideoEncodingProperties(*)(winrt::Windows::Foundation::IActivationFactory const&), VideoEncodingProperties>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<VideoEncodingProperties>(); }))
    {
    }
    inline auto VideoEncodingProperties::CreateH264()
    {
        return impl::call_factory_cast<winrt::Windows::Media::MediaProperties::VideoEncodingProperties(*)(IVideoEncodingPropertiesStatics const&), VideoEncodingProperties, IVideoEncodingPropertiesStatics>([](IVideoEncodingPropertiesStatics const& f) { return f.CreateH264(); });
    }
    inline auto VideoEncodingProperties::CreateMpeg2()
    {
        return impl::call_factory_cast<winrt::Windows::Media::MediaProperties::VideoEncodingProperties(*)(IVideoEncodingPropertiesStatics const&), VideoEncodingProperties, IVideoEncodingPropertiesStatics>([](IVideoEncodingPropertiesStatics const& f) { return f.CreateMpeg2(); });
    }
    inline auto VideoEncodingProperties::CreateUncompressed(param::hstring const& subtype, uint32_t width, uint32_t height)
    {
        return impl::call_factory<VideoEncodingProperties, IVideoEncodingPropertiesStatics>([&](IVideoEncodingPropertiesStatics const& f) { return f.CreateUncompressed(subtype, width, height); });
    }
    inline auto VideoEncodingProperties::CreateHevc()
    {
        return impl::call_factory_cast<winrt::Windows::Media::MediaProperties::VideoEncodingProperties(*)(IVideoEncodingPropertiesStatics2 const&), VideoEncodingProperties, IVideoEncodingPropertiesStatics2>([](IVideoEncodingPropertiesStatics2 const& f) { return f.CreateHevc(); });
    }
    inline auto VideoEncodingProperties::CreateVp9()
    {
        return impl::call_factory_cast<winrt::Windows::Media::MediaProperties::VideoEncodingProperties(*)(IVideoEncodingPropertiesStatics3 const&), VideoEncodingProperties, IVideoEncodingPropertiesStatics3>([](IVideoEncodingPropertiesStatics3 const& f) { return f.CreateVp9(); });
    }
    inline auto VideoEncodingProperties::CreateAv1()
    {
        return impl::call_factory_cast<winrt::Windows::Media::MediaProperties::VideoEncodingProperties(*)(IVideoEncodingPropertiesStatics3 const&), VideoEncodingProperties, IVideoEncodingPropertiesStatics3>([](IVideoEncodingPropertiesStatics3 const& f) { return f.CreateAv1(); });
    }
    inline auto Vp9ProfileIds::Profile0ChromaSubsampling420BitDepth8()
    {
        return impl::call_factory_cast<int32_t(*)(IVp9ProfileIdsStatics const&), Vp9ProfileIds, IVp9ProfileIdsStatics>([](IVp9ProfileIdsStatics const& f) { return f.Profile0ChromaSubsampling420BitDepth8(); });
    }
    inline auto Vp9ProfileIds::Profile2ChromaSubsampling420BitDepth10()
    {
        return impl::call_factory_cast<int32_t(*)(IVp9ProfileIdsStatics const&), Vp9ProfileIds, IVp9ProfileIdsStatics>([](IVp9ProfileIdsStatics const& f) { return f.Profile2ChromaSubsampling420BitDepth10(); });
    }
    inline auto Vp9ProfileIds::Profile2ChromaSubsampling420BitDepth12()
    {
        return impl::call_factory_cast<int32_t(*)(IVp9ProfileIdsStatics const&), Vp9ProfileIds, IVp9ProfileIdsStatics>([](IVp9ProfileIdsStatics const& f) { return f.Profile2ChromaSubsampling420BitDepth12(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Media::MediaProperties::IAudioEncodingProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IAudioEncodingProperties2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IAudioEncodingProperties3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IAudioEncodingPropertiesStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IAudioEncodingPropertiesWithFormatUserData> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IAv1ProfileIdsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IContainerEncodingProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IContainerEncodingProperties2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IH264ProfileIdsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IHevcProfileIdsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IImageEncodingProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IImageEncodingProperties2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IImageEncodingPropertiesStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IImageEncodingPropertiesStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IImageEncodingPropertiesStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IMediaEncodingProfile> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IMediaEncodingProfile2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IMediaEncodingProfile3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IMediaEncodingProfileStatics4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IMediaEncodingProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics6> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IMediaEncodingSubtypesStatics7> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IMediaRatio> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IMpeg2ProfileIdsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::ITimedMetadataEncodingProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::ITimedMetadataEncodingPropertiesStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IVideoEncodingProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IVideoEncodingProperties2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IVideoEncodingProperties3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IVideoEncodingProperties4> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IVideoEncodingProperties5> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IVideoEncodingPropertiesStatics3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::IVp9ProfileIdsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::AudioEncodingProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::Av1ProfileIds> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::ContainerEncodingProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::H264ProfileIds> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::HevcProfileIds> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::ImageEncodingProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::MediaEncodingProfile> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::MediaEncodingSubtypes> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::MediaPropertySet> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::MediaRatio> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::Mpeg2ProfileIds> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::TimedMetadataEncodingProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::VideoEncodingProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::MediaProperties::Vp9ProfileIds> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
