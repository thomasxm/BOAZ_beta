// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_Audio_H
#define WINRT_Windows_Media_Audio_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Media.h"
#include "winrt/impl/Windows.Devices.Enumeration.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Foundation.Numerics.2.h"
#include "winrt/impl/Windows.Media.2.h"
#include "winrt/impl/Windows.Media.Capture.2.h"
#include "winrt/impl/Windows.Media.Core.2.h"
#include "winrt/impl/Windows.Media.Devices.2.h"
#include "winrt/impl/Windows.Media.Effects.2.h"
#include "winrt/impl/Windows.Media.MediaProperties.2.h"
#include "winrt/impl/Windows.Media.Render.2.h"
#include "winrt/impl/Windows.Media.Transcoding.2.h"
#include "winrt/impl/Windows.Storage.2.h"
#include "winrt/impl/Windows.Media.Audio.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceInformation) consume_Windows_Media_Audio_IAudioDeviceInputNode<D>::Device() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioDeviceInputNode)->get_Device(&value));
        return winrt::Windows::Devices::Enumeration::DeviceInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceInformation) consume_Windows_Media_Audio_IAudioDeviceOutputNode<D>::Device() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioDeviceOutputNode)->get_Device(&value));
        return winrt::Windows::Devices::Enumeration::DeviceInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioFileInputNode<D>::PlaybackSpeedFactor(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioFileInputNode)->put_PlaybackSpeedFactor(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IAudioFileInputNode<D>::PlaybackSpeedFactor() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioFileInputNode)->get_PlaybackSpeedFactor(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Audio_IAudioFileInputNode<D>::Position() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioFileInputNode)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioFileInputNode<D>::Seek(winrt::Windows::Foundation::TimeSpan const& position) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioFileInputNode)->Seek(impl::bind_in(position)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Media_Audio_IAudioFileInputNode<D>::StartTime() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioFileInputNode)->get_StartTime(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioFileInputNode<D>::StartTime(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioFileInputNode)->put_StartTime(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Media_Audio_IAudioFileInputNode<D>::EndTime() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioFileInputNode)->get_EndTime(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioFileInputNode<D>::EndTime(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioFileInputNode)->put_EndTime(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_Media_Audio_IAudioFileInputNode<D>::LoopCount() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioFileInputNode)->get_LoopCount(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioFileInputNode<D>::LoopCount(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioFileInputNode)->put_LoopCount(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Audio_IAudioFileInputNode<D>::Duration() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioFileInputNode)->get_Duration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::StorageFile) consume_Windows_Media_Audio_IAudioFileInputNode<D>::SourceFile() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioFileInputNode)->get_SourceFile(&value));
        return winrt::Windows::Storage::StorageFile{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Audio_IAudioFileInputNode<D>::FileCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::AudioFileInputNode, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioFileInputNode)->add_FileCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Audio_IAudioFileInputNode<D>::FileCompleted_revoker consume_Windows_Media_Audio_IAudioFileInputNode<D>::FileCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::AudioFileInputNode, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, FileCompleted_revoker>(this, FileCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioFileInputNode<D>::FileCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioFileInputNode)->remove_FileCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::IStorageFile) consume_Windows_Media_Audio_IAudioFileOutputNode<D>::File() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioFileOutputNode)->get_File(&value));
        return winrt::Windows::Storage::IStorageFile{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::MediaEncodingProfile) consume_Windows_Media_Audio_IAudioFileOutputNode<D>::FileEncodingProfile() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioFileOutputNode)->get_FileEncodingProfile(&value));
        return winrt::Windows::Media::MediaProperties::MediaEncodingProfile{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Transcoding::TranscodeFailureReason>) consume_Windows_Media_Audio_IAudioFileOutputNode<D>::FinalizeAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioFileOutputNode)->FinalizeAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Transcoding::TranscodeFailureReason>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::AudioFrame) consume_Windows_Media_Audio_IAudioFrameCompletedEventArgs<D>::Frame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioFrameCompletedEventArgs)->get_Frame(&value));
        return winrt::Windows::Media::AudioFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioFrameInputNode<D>::PlaybackSpeedFactor(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioFrameInputNode)->put_PlaybackSpeedFactor(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IAudioFrameInputNode<D>::PlaybackSpeedFactor() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioFrameInputNode)->get_PlaybackSpeedFactor(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioFrameInputNode<D>::AddFrame(winrt::Windows::Media::AudioFrame const& frame) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioFrameInputNode)->AddFrame(*(void**)(&frame)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioFrameInputNode<D>::DiscardQueuedFrames() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioFrameInputNode)->DiscardQueuedFrames());
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_Media_Audio_IAudioFrameInputNode<D>::QueuedSampleCount() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioFrameInputNode)->get_QueuedSampleCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Audio_IAudioFrameInputNode<D>::AudioFrameCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::AudioFrameInputNode, winrt::Windows::Media::Audio::AudioFrameCompletedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioFrameInputNode)->add_AudioFrameCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Audio_IAudioFrameInputNode<D>::AudioFrameCompleted_revoker consume_Windows_Media_Audio_IAudioFrameInputNode<D>::AudioFrameCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::AudioFrameInputNode, winrt::Windows::Media::Audio::AudioFrameCompletedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, AudioFrameCompleted_revoker>(this, AudioFrameCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioFrameInputNode<D>::AudioFrameCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioFrameInputNode)->remove_AudioFrameCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Audio_IAudioFrameInputNode<D>::QuantumStarted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::AudioFrameInputNode, winrt::Windows::Media::Audio::FrameInputNodeQuantumStartedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioFrameInputNode)->add_QuantumStarted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Audio_IAudioFrameInputNode<D>::QuantumStarted_revoker consume_Windows_Media_Audio_IAudioFrameInputNode<D>::QuantumStarted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::AudioFrameInputNode, winrt::Windows::Media::Audio::FrameInputNodeQuantumStartedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, QuantumStarted_revoker>(this, QuantumStarted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioFrameInputNode<D>::QuantumStarted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioFrameInputNode)->remove_QuantumStarted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::AudioFrame) consume_Windows_Media_Audio_IAudioFrameOutputNode<D>::GetFrame() const
    {
        void* audioFrame{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioFrameOutputNode)->GetFrame(&audioFrame));
        return winrt::Windows::Media::AudioFrame{ audioFrame, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioFrameInputNode) consume_Windows_Media_Audio_IAudioGraph<D>::CreateFrameInputNode() const
    {
        void* frameInputNode{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph)->CreateFrameInputNode(&frameInputNode));
        return winrt::Windows::Media::Audio::AudioFrameInputNode{ frameInputNode, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioFrameInputNode) consume_Windows_Media_Audio_IAudioGraph<D>::CreateFrameInputNode(winrt::Windows::Media::MediaProperties::AudioEncodingProperties const& encodingProperties) const
    {
        void* frameInputNode{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph)->CreateFrameInputNodeWithFormat(*(void**)(&encodingProperties), &frameInputNode));
        return winrt::Windows::Media::Audio::AudioFrameInputNode{ frameInputNode, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioDeviceInputNodeResult>) consume_Windows_Media_Audio_IAudioGraph<D>::CreateDeviceInputNodeAsync(winrt::Windows::Media::Capture::MediaCategory const& category) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph)->CreateDeviceInputNodeAsync(static_cast<int32_t>(category), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioDeviceInputNodeResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioDeviceInputNodeResult>) consume_Windows_Media_Audio_IAudioGraph<D>::CreateDeviceInputNodeAsync(winrt::Windows::Media::Capture::MediaCategory const& category, winrt::Windows::Media::MediaProperties::AudioEncodingProperties const& encodingProperties) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph)->CreateDeviceInputNodeWithFormatAsync(static_cast<int32_t>(category), *(void**)(&encodingProperties), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioDeviceInputNodeResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioDeviceInputNodeResult>) consume_Windows_Media_Audio_IAudioGraph<D>::CreateDeviceInputNodeAsync(winrt::Windows::Media::Capture::MediaCategory const& category, winrt::Windows::Media::MediaProperties::AudioEncodingProperties const& encodingProperties, winrt::Windows::Devices::Enumeration::DeviceInformation const& device) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph)->CreateDeviceInputNodeWithFormatOnDeviceAsync(static_cast<int32_t>(category), *(void**)(&encodingProperties), *(void**)(&device), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioDeviceInputNodeResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioFrameOutputNode) consume_Windows_Media_Audio_IAudioGraph<D>::CreateFrameOutputNode() const
    {
        void* frameOutputNode{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph)->CreateFrameOutputNode(&frameOutputNode));
        return winrt::Windows::Media::Audio::AudioFrameOutputNode{ frameOutputNode, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioFrameOutputNode) consume_Windows_Media_Audio_IAudioGraph<D>::CreateFrameOutputNode(winrt::Windows::Media::MediaProperties::AudioEncodingProperties const& encodingProperties) const
    {
        void* frameOutputNode{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph)->CreateFrameOutputNodeWithFormat(*(void**)(&encodingProperties), &frameOutputNode));
        return winrt::Windows::Media::Audio::AudioFrameOutputNode{ frameOutputNode, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioDeviceOutputNodeResult>) consume_Windows_Media_Audio_IAudioGraph<D>::CreateDeviceOutputNodeAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph)->CreateDeviceOutputNodeAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioDeviceOutputNodeResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioFileInputNodeResult>) consume_Windows_Media_Audio_IAudioGraph<D>::CreateFileInputNodeAsync(winrt::Windows::Storage::IStorageFile const& file) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph)->CreateFileInputNodeAsync(*(void**)(&file), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioFileInputNodeResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioFileOutputNodeResult>) consume_Windows_Media_Audio_IAudioGraph<D>::CreateFileOutputNodeAsync(winrt::Windows::Storage::IStorageFile const& file) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph)->CreateFileOutputNodeAsync(*(void**)(&file), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioFileOutputNodeResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioFileOutputNodeResult>) consume_Windows_Media_Audio_IAudioGraph<D>::CreateFileOutputNodeAsync(winrt::Windows::Storage::IStorageFile const& file, winrt::Windows::Media::MediaProperties::MediaEncodingProfile const& fileEncodingProfile) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph)->CreateFileOutputNodeWithFileProfileAsync(*(void**)(&file), *(void**)(&fileEncodingProfile), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioFileOutputNodeResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioSubmixNode) consume_Windows_Media_Audio_IAudioGraph<D>::CreateSubmixNode() const
    {
        void* submixNode{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph)->CreateSubmixNode(&submixNode));
        return winrt::Windows::Media::Audio::AudioSubmixNode{ submixNode, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioSubmixNode) consume_Windows_Media_Audio_IAudioGraph<D>::CreateSubmixNode(winrt::Windows::Media::MediaProperties::AudioEncodingProperties const& encodingProperties) const
    {
        void* submixNode{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph)->CreateSubmixNodeWithFormat(*(void**)(&encodingProperties), &submixNode));
        return winrt::Windows::Media::Audio::AudioSubmixNode{ submixNode, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioGraph<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioGraph<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioGraph<D>::ResetAllNodes() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph)->ResetAllNodes());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Audio_IAudioGraph<D>::QuantumStarted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::AudioGraph, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph)->add_QuantumStarted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Audio_IAudioGraph<D>::QuantumStarted_revoker consume_Windows_Media_Audio_IAudioGraph<D>::QuantumStarted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::AudioGraph, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, QuantumStarted_revoker>(this, QuantumStarted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioGraph<D>::QuantumStarted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph)->remove_QuantumStarted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Audio_IAudioGraph<D>::QuantumProcessed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::AudioGraph, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph)->add_QuantumProcessed(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Audio_IAudioGraph<D>::QuantumProcessed_revoker consume_Windows_Media_Audio_IAudioGraph<D>::QuantumProcessed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::AudioGraph, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, QuantumProcessed_revoker>(this, QuantumProcessed(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioGraph<D>::QuantumProcessed(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph)->remove_QuantumProcessed(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Audio_IAudioGraph<D>::UnrecoverableErrorOccurred(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::AudioGraph, winrt::Windows::Media::Audio::AudioGraphUnrecoverableErrorOccurredEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph)->add_UnrecoverableErrorOccurred(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Audio_IAudioGraph<D>::UnrecoverableErrorOccurred_revoker consume_Windows_Media_Audio_IAudioGraph<D>::UnrecoverableErrorOccurred(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::AudioGraph, winrt::Windows::Media::Audio::AudioGraphUnrecoverableErrorOccurredEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, UnrecoverableErrorOccurred_revoker>(this, UnrecoverableErrorOccurred(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioGraph<D>::UnrecoverableErrorOccurred(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph)->remove_UnrecoverableErrorOccurred(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(uint64_t) consume_Windows_Media_Audio_IAudioGraph<D>::CompletedQuantumCount() const
    {
        uint64_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph)->get_CompletedQuantumCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::AudioEncodingProperties) consume_Windows_Media_Audio_IAudioGraph<D>::EncodingProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph)->get_EncodingProperties(&value));
        return winrt::Windows::Media::MediaProperties::AudioEncodingProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_Audio_IAudioGraph<D>::LatencyInSamples() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph)->get_LatencyInSamples(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceInformation) consume_Windows_Media_Audio_IAudioGraph<D>::PrimaryRenderDevice() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph)->get_PrimaryRenderDevice(&value));
        return winrt::Windows::Devices::Enumeration::DeviceInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::AudioProcessing) consume_Windows_Media_Audio_IAudioGraph<D>::RenderDeviceAudioProcessing() const
    {
        winrt::Windows::Media::AudioProcessing value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph)->get_RenderDeviceAudioProcessing(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_Audio_IAudioGraph<D>::SamplesPerQuantum() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph)->get_SamplesPerQuantum(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioFrameInputNode) consume_Windows_Media_Audio_IAudioGraph2<D>::CreateFrameInputNode(winrt::Windows::Media::MediaProperties::AudioEncodingProperties const& encodingProperties, winrt::Windows::Media::Audio::AudioNodeEmitter const& emitter) const
    {
        void* frameInputNode{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph2)->CreateFrameInputNodeWithFormatAndEmitter(*(void**)(&encodingProperties), *(void**)(&emitter), &frameInputNode));
        return winrt::Windows::Media::Audio::AudioFrameInputNode{ frameInputNode, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioDeviceInputNodeResult>) consume_Windows_Media_Audio_IAudioGraph2<D>::CreateDeviceInputNodeAsync(winrt::Windows::Media::Capture::MediaCategory const& category, winrt::Windows::Media::MediaProperties::AudioEncodingProperties const& encodingProperties, winrt::Windows::Devices::Enumeration::DeviceInformation const& device, winrt::Windows::Media::Audio::AudioNodeEmitter const& emitter) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph2)->CreateDeviceInputNodeWithFormatAndEmitterOnDeviceAsync(static_cast<int32_t>(category), *(void**)(&encodingProperties), *(void**)(&device), *(void**)(&emitter), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioDeviceInputNodeResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioFileInputNodeResult>) consume_Windows_Media_Audio_IAudioGraph2<D>::CreateFileInputNodeAsync(winrt::Windows::Storage::IStorageFile const& file, winrt::Windows::Media::Audio::AudioNodeEmitter const& emitter) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph2)->CreateFileInputNodeWithEmitterAsync(*(void**)(&file), *(void**)(&emitter), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioFileInputNodeResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioSubmixNode) consume_Windows_Media_Audio_IAudioGraph2<D>::CreateSubmixNode(winrt::Windows::Media::MediaProperties::AudioEncodingProperties const& encodingProperties, winrt::Windows::Media::Audio::AudioNodeEmitter const& emitter) const
    {
        void* submixNode{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph2)->CreateSubmixNodeWithFormatAndEmitter(*(void**)(&encodingProperties), *(void**)(&emitter), &submixNode));
        return winrt::Windows::Media::Audio::AudioSubmixNode{ submixNode, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioGraphBatchUpdater) consume_Windows_Media_Audio_IAudioGraph2<D>::CreateBatchUpdater() const
    {
        void* updater{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph2)->CreateBatchUpdater(&updater));
        return winrt::Windows::Media::Audio::AudioGraphBatchUpdater{ updater, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateMediaSourceAudioInputNodeResult>) consume_Windows_Media_Audio_IAudioGraph3<D>::CreateMediaSourceAudioInputNodeAsync(winrt::Windows::Media::Core::MediaSource const& mediaSource) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph3)->CreateMediaSourceAudioInputNodeAsync(*(void**)(&mediaSource), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateMediaSourceAudioInputNodeResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateMediaSourceAudioInputNodeResult>) consume_Windows_Media_Audio_IAudioGraph3<D>::CreateMediaSourceAudioInputNodeAsync(winrt::Windows::Media::Core::MediaSource const& mediaSource, winrt::Windows::Media::Audio::AudioNodeEmitter const& emitter) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraph3)->CreateMediaSourceAudioInputNodeWithEmitterAsync(*(void**)(&mediaSource), *(void**)(&emitter), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateMediaSourceAudioInputNodeResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::IAudioNode) consume_Windows_Media_Audio_IAudioGraphConnection<D>::Destination() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraphConnection)->get_Destination(&value));
        return winrt::Windows::Media::Audio::IAudioNode{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioGraphConnection<D>::Gain(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraphConnection)->put_Gain(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IAudioGraphConnection<D>::Gain() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraphConnection)->get_Gain(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::AudioEncodingProperties) consume_Windows_Media_Audio_IAudioGraphSettings<D>::EncodingProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraphSettings)->get_EncodingProperties(&value));
        return winrt::Windows::Media::MediaProperties::AudioEncodingProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioGraphSettings<D>::EncodingProperties(winrt::Windows::Media::MediaProperties::AudioEncodingProperties const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraphSettings)->put_EncodingProperties(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceInformation) consume_Windows_Media_Audio_IAudioGraphSettings<D>::PrimaryRenderDevice() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraphSettings)->get_PrimaryRenderDevice(&value));
        return winrt::Windows::Devices::Enumeration::DeviceInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioGraphSettings<D>::PrimaryRenderDevice(winrt::Windows::Devices::Enumeration::DeviceInformation const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraphSettings)->put_PrimaryRenderDevice(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::QuantumSizeSelectionMode) consume_Windows_Media_Audio_IAudioGraphSettings<D>::QuantumSizeSelectionMode() const
    {
        winrt::Windows::Media::Audio::QuantumSizeSelectionMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraphSettings)->get_QuantumSizeSelectionMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioGraphSettings<D>::QuantumSizeSelectionMode(winrt::Windows::Media::Audio::QuantumSizeSelectionMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraphSettings)->put_QuantumSizeSelectionMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_Audio_IAudioGraphSettings<D>::DesiredSamplesPerQuantum() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraphSettings)->get_DesiredSamplesPerQuantum(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioGraphSettings<D>::DesiredSamplesPerQuantum(int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraphSettings)->put_DesiredSamplesPerQuantum(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Render::AudioRenderCategory) consume_Windows_Media_Audio_IAudioGraphSettings<D>::AudioRenderCategory() const
    {
        winrt::Windows::Media::Render::AudioRenderCategory value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraphSettings)->get_AudioRenderCategory(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioGraphSettings<D>::AudioRenderCategory(winrt::Windows::Media::Render::AudioRenderCategory const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraphSettings)->put_AudioRenderCategory(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::AudioProcessing) consume_Windows_Media_Audio_IAudioGraphSettings<D>::DesiredRenderDeviceAudioProcessing() const
    {
        winrt::Windows::Media::AudioProcessing value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraphSettings)->get_DesiredRenderDeviceAudioProcessing(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioGraphSettings<D>::DesiredRenderDeviceAudioProcessing(winrt::Windows::Media::AudioProcessing const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraphSettings)->put_DesiredRenderDeviceAudioProcessing(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioGraphSettings2<D>::MaxPlaybackSpeedFactor(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraphSettings2)->put_MaxPlaybackSpeedFactor(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IAudioGraphSettings2<D>::MaxPlaybackSpeedFactor() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraphSettings2)->get_MaxPlaybackSpeedFactor(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioGraphSettings) consume_Windows_Media_Audio_IAudioGraphSettingsFactory<D>::Create(winrt::Windows::Media::Render::AudioRenderCategory const& audioRenderCategory) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraphSettingsFactory)->Create(static_cast<int32_t>(audioRenderCategory), &value));
        return winrt::Windows::Media::Audio::AudioGraphSettings{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioGraphResult>) consume_Windows_Media_Audio_IAudioGraphStatics<D>::CreateAsync(winrt::Windows::Media::Audio::AudioGraphSettings const& settings) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraphStatics)->CreateAsync(*(void**)(&settings), &result));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioGraphResult>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioGraphUnrecoverableError) consume_Windows_Media_Audio_IAudioGraphUnrecoverableErrorOccurredEventArgs<D>::Error() const
    {
        winrt::Windows::Media::Audio::AudioGraphUnrecoverableError value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioGraphUnrecoverableErrorOccurredEventArgs)->get_Error(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Audio::AudioGraphConnection>) consume_Windows_Media_Audio_IAudioInputNode<D>::OutgoingConnections() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioInputNode)->get_OutgoingConnections(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Audio::AudioGraphConnection>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioInputNode<D>::AddOutgoingConnection(winrt::Windows::Media::Audio::IAudioNode const& destination) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioInputNode)->AddOutgoingConnection(*(void**)(&destination)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioInputNode<D>::AddOutgoingConnection(winrt::Windows::Media::Audio::IAudioNode const& destination, double gain) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioInputNode)->AddOutgoingConnectionWithGain(*(void**)(&destination), gain));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioInputNode<D>::RemoveOutgoingConnection(winrt::Windows::Media::Audio::IAudioNode const& destination) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioInputNode)->RemoveOutgoingConnection(*(void**)(&destination)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioNodeEmitter) consume_Windows_Media_Audio_IAudioInputNode2<D>::Emitter() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioInputNode2)->get_Emitter(&value));
        return winrt::Windows::Media::Audio::AudioNodeEmitter{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Media::Effects::IAudioEffectDefinition>) consume_Windows_Media_Audio_IAudioNode<D>::EffectDefinitions() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNode)->get_EffectDefinitions(&value));
        return winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Media::Effects::IAudioEffectDefinition>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioNode<D>::OutgoingGain(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNode)->put_OutgoingGain(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IAudioNode<D>::OutgoingGain() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNode)->get_OutgoingGain(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::AudioEncodingProperties) consume_Windows_Media_Audio_IAudioNode<D>::EncodingProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNode)->get_EncodingProperties(&value));
        return winrt::Windows::Media::MediaProperties::AudioEncodingProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Audio_IAudioNode<D>::ConsumeInput() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNode)->get_ConsumeInput(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioNode<D>::ConsumeInput(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNode)->put_ConsumeInput(value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioNode<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNode)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioNode<D>::Stop() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNode)->Stop());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioNode<D>::Reset() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNode)->Reset());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioNode<D>::DisableEffectsByDefinition(winrt::Windows::Media::Effects::IAudioEffectDefinition const& definition) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNode)->DisableEffectsByDefinition(*(void**)(&definition)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioNode<D>::EnableEffectsByDefinition(winrt::Windows::Media::Effects::IAudioEffectDefinition const& definition) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNode)->EnableEffectsByDefinition(*(void**)(&definition)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_Media_Audio_IAudioNodeEmitter<D>::Position() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitter)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioNodeEmitter<D>::Position(winrt::Windows::Foundation::Numerics::float3 const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitter)->put_Position(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_Media_Audio_IAudioNodeEmitter<D>::Direction() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitter)->get_Direction(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioNodeEmitter<D>::Direction(winrt::Windows::Foundation::Numerics::float3 const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitter)->put_Direction(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioNodeEmitterShape) consume_Windows_Media_Audio_IAudioNodeEmitter<D>::Shape() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitter)->get_Shape(&value));
        return winrt::Windows::Media::Audio::AudioNodeEmitterShape{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioNodeEmitterDecayModel) consume_Windows_Media_Audio_IAudioNodeEmitter<D>::DecayModel() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitter)->get_DecayModel(&value));
        return winrt::Windows::Media::Audio::AudioNodeEmitterDecayModel{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IAudioNodeEmitter<D>::Gain() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitter)->get_Gain(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioNodeEmitter<D>::Gain(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitter)->put_Gain(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IAudioNodeEmitter<D>::DistanceScale() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitter)->get_DistanceScale(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioNodeEmitter<D>::DistanceScale(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitter)->put_DistanceScale(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IAudioNodeEmitter<D>::DopplerScale() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitter)->get_DopplerScale(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioNodeEmitter<D>::DopplerScale(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitter)->put_DopplerScale(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_Media_Audio_IAudioNodeEmitter<D>::DopplerVelocity() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitter)->get_DopplerVelocity(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioNodeEmitter<D>::DopplerVelocity(winrt::Windows::Foundation::Numerics::float3 const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitter)->put_DopplerVelocity(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Audio_IAudioNodeEmitter<D>::IsDopplerDisabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitter)->get_IsDopplerDisabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::SpatialAudioModel) consume_Windows_Media_Audio_IAudioNodeEmitter2<D>::SpatialAudioModel() const
    {
        winrt::Windows::Media::Audio::SpatialAudioModel value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitter2)->get_SpatialAudioModel(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioNodeEmitter2<D>::SpatialAudioModel(winrt::Windows::Media::Audio::SpatialAudioModel const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitter2)->put_SpatialAudioModel(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IAudioNodeEmitterConeProperties<D>::InnerAngle() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitterConeProperties)->get_InnerAngle(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IAudioNodeEmitterConeProperties<D>::OuterAngle() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitterConeProperties)->get_OuterAngle(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IAudioNodeEmitterConeProperties<D>::OuterAngleGain() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitterConeProperties)->get_OuterAngleGain(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioNodeEmitterDecayKind) consume_Windows_Media_Audio_IAudioNodeEmitterDecayModel<D>::Kind() const
    {
        winrt::Windows::Media::Audio::AudioNodeEmitterDecayKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitterDecayModel)->get_Kind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IAudioNodeEmitterDecayModel<D>::MinGain() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitterDecayModel)->get_MinGain(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IAudioNodeEmitterDecayModel<D>::MaxGain() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitterDecayModel)->get_MaxGain(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioNodeEmitterNaturalDecayModelProperties) consume_Windows_Media_Audio_IAudioNodeEmitterDecayModel<D>::NaturalProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitterDecayModel)->get_NaturalProperties(&value));
        return winrt::Windows::Media::Audio::AudioNodeEmitterNaturalDecayModelProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioNodeEmitterDecayModel) consume_Windows_Media_Audio_IAudioNodeEmitterDecayModelStatics<D>::CreateNatural(double minGain, double maxGain, double unityGainDistance, double cutoffDistance) const
    {
        void* decayModel{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitterDecayModelStatics)->CreateNatural(minGain, maxGain, unityGainDistance, cutoffDistance, &decayModel));
        return winrt::Windows::Media::Audio::AudioNodeEmitterDecayModel{ decayModel, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioNodeEmitterDecayModel) consume_Windows_Media_Audio_IAudioNodeEmitterDecayModelStatics<D>::CreateCustom(double minGain, double maxGain) const
    {
        void* decayModel{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitterDecayModelStatics)->CreateCustom(minGain, maxGain, &decayModel));
        return winrt::Windows::Media::Audio::AudioNodeEmitterDecayModel{ decayModel, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioNodeEmitter) consume_Windows_Media_Audio_IAudioNodeEmitterFactory<D>::CreateAudioNodeEmitter(winrt::Windows::Media::Audio::AudioNodeEmitterShape const& shape, winrt::Windows::Media::Audio::AudioNodeEmitterDecayModel const& decayModel, winrt::Windows::Media::Audio::AudioNodeEmitterSettings const& settings) const
    {
        void* emitter{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitterFactory)->CreateAudioNodeEmitter(*(void**)(&shape), *(void**)(&decayModel), static_cast<uint32_t>(settings), &emitter));
        return winrt::Windows::Media::Audio::AudioNodeEmitter{ emitter, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IAudioNodeEmitterNaturalDecayModelProperties<D>::UnityGainDistance() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitterNaturalDecayModelProperties)->get_UnityGainDistance(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IAudioNodeEmitterNaturalDecayModelProperties<D>::CutoffDistance() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitterNaturalDecayModelProperties)->get_CutoffDistance(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioNodeEmitterShapeKind) consume_Windows_Media_Audio_IAudioNodeEmitterShape<D>::Kind() const
    {
        winrt::Windows::Media::Audio::AudioNodeEmitterShapeKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitterShape)->get_Kind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioNodeEmitterConeProperties) consume_Windows_Media_Audio_IAudioNodeEmitterShape<D>::ConeProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitterShape)->get_ConeProperties(&value));
        return winrt::Windows::Media::Audio::AudioNodeEmitterConeProperties{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioNodeEmitterShape) consume_Windows_Media_Audio_IAudioNodeEmitterShapeStatics<D>::CreateCone(double innerAngle, double outerAngle, double outerAngleGain) const
    {
        void* shape{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitterShapeStatics)->CreateCone(innerAngle, outerAngle, outerAngleGain, &shape));
        return winrt::Windows::Media::Audio::AudioNodeEmitterShape{ shape, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioNodeEmitterShape) consume_Windows_Media_Audio_IAudioNodeEmitterShapeStatics<D>::CreateOmnidirectional() const
    {
        void* shape{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeEmitterShapeStatics)->CreateOmnidirectional(&shape));
        return winrt::Windows::Media::Audio::AudioNodeEmitterShape{ shape, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_Media_Audio_IAudioNodeListener<D>::Position() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeListener)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioNodeListener<D>::Position(winrt::Windows::Foundation::Numerics::float3 const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeListener)->put_Position(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::quaternion) consume_Windows_Media_Audio_IAudioNodeListener<D>::Orientation() const
    {
        winrt::Windows::Foundation::Numerics::quaternion value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeListener)->get_Orientation(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioNodeListener<D>::Orientation(winrt::Windows::Foundation::Numerics::quaternion const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeListener)->put_Orientation(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IAudioNodeListener<D>::SpeedOfSound() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeListener)->get_SpeedOfSound(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioNodeListener<D>::SpeedOfSound(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeListener)->put_SpeedOfSound(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::float3) consume_Windows_Media_Audio_IAudioNodeListener<D>::DopplerVelocity() const
    {
        winrt::Windows::Foundation::Numerics::float3 value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeListener)->get_DopplerVelocity(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioNodeListener<D>::DopplerVelocity(winrt::Windows::Foundation::Numerics::float3 const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeListener)->put_DopplerVelocity(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioNodeWithListener<D>::Listener(winrt::Windows::Media::Audio::AudioNodeListener const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeWithListener)->put_Listener(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioNodeListener) consume_Windows_Media_Audio_IAudioNodeWithListener<D>::Listener() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioNodeWithListener)->get_Listener(&value));
        return winrt::Windows::Media::Audio::AudioNodeListener{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioPlaybackConnection<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioPlaybackConnection)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Audio_IAudioPlaybackConnection<D>::StartAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioPlaybackConnection)->StartAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Audio_IAudioPlaybackConnection<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioPlaybackConnection)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioPlaybackConnectionState) consume_Windows_Media_Audio_IAudioPlaybackConnection<D>::State() const
    {
        winrt::Windows::Media::Audio::AudioPlaybackConnectionState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioPlaybackConnection)->get_State(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioPlaybackConnectionOpenResult) consume_Windows_Media_Audio_IAudioPlaybackConnection<D>::Open() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioPlaybackConnection)->Open(&result));
        return winrt::Windows::Media::Audio::AudioPlaybackConnectionOpenResult{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::AudioPlaybackConnectionOpenResult>) consume_Windows_Media_Audio_IAudioPlaybackConnection<D>::OpenAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioPlaybackConnection)->OpenAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::AudioPlaybackConnectionOpenResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Audio_IAudioPlaybackConnection<D>::StateChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::AudioPlaybackConnection, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioPlaybackConnection)->add_StateChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Audio_IAudioPlaybackConnection<D>::StateChanged_revoker consume_Windows_Media_Audio_IAudioPlaybackConnection<D>::StateChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::AudioPlaybackConnection, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, StateChanged_revoker>(this, StateChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioPlaybackConnection<D>::StateChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioPlaybackConnection)->remove_StateChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioPlaybackConnectionOpenResultStatus) consume_Windows_Media_Audio_IAudioPlaybackConnectionOpenResult<D>::Status() const
    {
        winrt::Windows::Media::Audio::AudioPlaybackConnectionOpenResultStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioPlaybackConnectionOpenResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Media_Audio_IAudioPlaybackConnectionOpenResult<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioPlaybackConnectionOpenResult)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Audio_IAudioPlaybackConnectionStatics<D>::GetDeviceSelector() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioPlaybackConnectionStatics)->GetDeviceSelector(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioPlaybackConnection) consume_Windows_Media_Audio_IAudioPlaybackConnectionStatics<D>::TryCreateFromId(param::hstring const& id) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioPlaybackConnectionStatics)->TryCreateFromId(*(void**)(&id), &result));
        return winrt::Windows::Media::Audio::AudioPlaybackConnection{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Audio_IAudioStateMonitor<D>::SoundLevelChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::AudioStateMonitor, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioStateMonitor)->add_SoundLevelChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Audio_IAudioStateMonitor<D>::SoundLevelChanged_revoker consume_Windows_Media_Audio_IAudioStateMonitor<D>::SoundLevelChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::AudioStateMonitor, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, SoundLevelChanged_revoker>(this, SoundLevelChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IAudioStateMonitor<D>::SoundLevelChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioStateMonitor)->remove_SoundLevelChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SoundLevel) consume_Windows_Media_Audio_IAudioStateMonitor<D>::SoundLevel() const
    {
        winrt::Windows::Media::SoundLevel value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioStateMonitor)->get_SoundLevel(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioStateMonitor) consume_Windows_Media_Audio_IAudioStateMonitorStatics<D>::CreateForRenderMonitoring() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioStateMonitorStatics)->CreateForRenderMonitoring(&result));
        return winrt::Windows::Media::Audio::AudioStateMonitor{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioStateMonitor) consume_Windows_Media_Audio_IAudioStateMonitorStatics<D>::CreateForRenderMonitoring(winrt::Windows::Media::Render::AudioRenderCategory const& category) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioStateMonitorStatics)->CreateForRenderMonitoringWithCategory(static_cast<int32_t>(category), &result));
        return winrt::Windows::Media::Audio::AudioStateMonitor{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioStateMonitor) consume_Windows_Media_Audio_IAudioStateMonitorStatics<D>::CreateForRenderMonitoring(winrt::Windows::Media::Render::AudioRenderCategory const& category, winrt::Windows::Media::Devices::AudioDeviceRole const& role) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioStateMonitorStatics)->CreateForRenderMonitoringWithCategoryAndDeviceRole(static_cast<int32_t>(category), static_cast<int32_t>(role), &result));
        return winrt::Windows::Media::Audio::AudioStateMonitor{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioStateMonitor) consume_Windows_Media_Audio_IAudioStateMonitorStatics<D>::CreateForRenderMonitoringWithCategoryAndDeviceId(winrt::Windows::Media::Render::AudioRenderCategory const& category, param::hstring const& deviceId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioStateMonitorStatics)->CreateForRenderMonitoringWithCategoryAndDeviceId(static_cast<int32_t>(category), *(void**)(&deviceId), &result));
        return winrt::Windows::Media::Audio::AudioStateMonitor{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioStateMonitor) consume_Windows_Media_Audio_IAudioStateMonitorStatics<D>::CreateForCaptureMonitoring() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioStateMonitorStatics)->CreateForCaptureMonitoring(&result));
        return winrt::Windows::Media::Audio::AudioStateMonitor{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioStateMonitor) consume_Windows_Media_Audio_IAudioStateMonitorStatics<D>::CreateForCaptureMonitoring(winrt::Windows::Media::Capture::MediaCategory const& category) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioStateMonitorStatics)->CreateForCaptureMonitoringWithCategory(static_cast<int32_t>(category), &result));
        return winrt::Windows::Media::Audio::AudioStateMonitor{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioStateMonitor) consume_Windows_Media_Audio_IAudioStateMonitorStatics<D>::CreateForCaptureMonitoring(winrt::Windows::Media::Capture::MediaCategory const& category, winrt::Windows::Media::Devices::AudioDeviceRole const& role) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioStateMonitorStatics)->CreateForCaptureMonitoringWithCategoryAndDeviceRole(static_cast<int32_t>(category), static_cast<int32_t>(role), &result));
        return winrt::Windows::Media::Audio::AudioStateMonitor{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioStateMonitor) consume_Windows_Media_Audio_IAudioStateMonitorStatics<D>::CreateForCaptureMonitoringWithCategoryAndDeviceId(winrt::Windows::Media::Capture::MediaCategory const& category, param::hstring const& deviceId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IAudioStateMonitorStatics)->CreateForCaptureMonitoringWithCategoryAndDeviceId(static_cast<int32_t>(category), *(void**)(&deviceId), &result));
        return winrt::Windows::Media::Audio::AudioStateMonitor{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioDeviceNodeCreationStatus) consume_Windows_Media_Audio_ICreateAudioDeviceInputNodeResult<D>::Status() const
    {
        winrt::Windows::Media::Audio::AudioDeviceNodeCreationStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ICreateAudioDeviceInputNodeResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioDeviceInputNode) consume_Windows_Media_Audio_ICreateAudioDeviceInputNodeResult<D>::DeviceInputNode() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ICreateAudioDeviceInputNodeResult)->get_DeviceInputNode(&value));
        return winrt::Windows::Media::Audio::AudioDeviceInputNode{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Media_Audio_ICreateAudioDeviceInputNodeResult2<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ICreateAudioDeviceInputNodeResult2)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioDeviceNodeCreationStatus) consume_Windows_Media_Audio_ICreateAudioDeviceOutputNodeResult<D>::Status() const
    {
        winrt::Windows::Media::Audio::AudioDeviceNodeCreationStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ICreateAudioDeviceOutputNodeResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioDeviceOutputNode) consume_Windows_Media_Audio_ICreateAudioDeviceOutputNodeResult<D>::DeviceOutputNode() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ICreateAudioDeviceOutputNodeResult)->get_DeviceOutputNode(&value));
        return winrt::Windows::Media::Audio::AudioDeviceOutputNode{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Media_Audio_ICreateAudioDeviceOutputNodeResult2<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ICreateAudioDeviceOutputNodeResult2)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioFileNodeCreationStatus) consume_Windows_Media_Audio_ICreateAudioFileInputNodeResult<D>::Status() const
    {
        winrt::Windows::Media::Audio::AudioFileNodeCreationStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ICreateAudioFileInputNodeResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioFileInputNode) consume_Windows_Media_Audio_ICreateAudioFileInputNodeResult<D>::FileInputNode() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ICreateAudioFileInputNodeResult)->get_FileInputNode(&value));
        return winrt::Windows::Media::Audio::AudioFileInputNode{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Media_Audio_ICreateAudioFileInputNodeResult2<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ICreateAudioFileInputNodeResult2)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioFileNodeCreationStatus) consume_Windows_Media_Audio_ICreateAudioFileOutputNodeResult<D>::Status() const
    {
        winrt::Windows::Media::Audio::AudioFileNodeCreationStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ICreateAudioFileOutputNodeResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioFileOutputNode) consume_Windows_Media_Audio_ICreateAudioFileOutputNodeResult<D>::FileOutputNode() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ICreateAudioFileOutputNodeResult)->get_FileOutputNode(&value));
        return winrt::Windows::Media::Audio::AudioFileOutputNode{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Media_Audio_ICreateAudioFileOutputNodeResult2<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ICreateAudioFileOutputNodeResult2)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioGraphCreationStatus) consume_Windows_Media_Audio_ICreateAudioGraphResult<D>::Status() const
    {
        winrt::Windows::Media::Audio::AudioGraphCreationStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ICreateAudioGraphResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::AudioGraph) consume_Windows_Media_Audio_ICreateAudioGraphResult<D>::Graph() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ICreateAudioGraphResult)->get_Graph(&value));
        return winrt::Windows::Media::Audio::AudioGraph{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Media_Audio_ICreateAudioGraphResult2<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ICreateAudioGraphResult2)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::MediaSourceAudioInputNodeCreationStatus) consume_Windows_Media_Audio_ICreateMediaSourceAudioInputNodeResult<D>::Status() const
    {
        winrt::Windows::Media::Audio::MediaSourceAudioInputNodeCreationStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ICreateMediaSourceAudioInputNodeResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::MediaSourceAudioInputNode) consume_Windows_Media_Audio_ICreateMediaSourceAudioInputNodeResult<D>::Node() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ICreateMediaSourceAudioInputNodeResult)->get_Node(&value));
        return winrt::Windows::Media::Audio::MediaSourceAudioInputNode{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Media_Audio_ICreateMediaSourceAudioInputNodeResult2<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ICreateMediaSourceAudioInputNodeResult2)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IEchoEffectDefinition<D>::WetDryMix(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IEchoEffectDefinition)->put_WetDryMix(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IEchoEffectDefinition<D>::WetDryMix() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IEchoEffectDefinition)->get_WetDryMix(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IEchoEffectDefinition<D>::Feedback(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IEchoEffectDefinition)->put_Feedback(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IEchoEffectDefinition<D>::Feedback() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IEchoEffectDefinition)->get_Feedback(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IEchoEffectDefinition<D>::Delay(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IEchoEffectDefinition)->put_Delay(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IEchoEffectDefinition<D>::Delay() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IEchoEffectDefinition)->get_Delay(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::EchoEffectDefinition) consume_Windows_Media_Audio_IEchoEffectDefinitionFactory<D>::Create(winrt::Windows::Media::Audio::AudioGraph const& audioGraph) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IEchoEffectDefinitionFactory)->Create(*(void**)(&audioGraph), &value));
        return winrt::Windows::Media::Audio::EchoEffectDefinition{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IEqualizerBand<D>::Bandwidth() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IEqualizerBand)->get_Bandwidth(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IEqualizerBand<D>::Bandwidth(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IEqualizerBand)->put_Bandwidth(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IEqualizerBand<D>::FrequencyCenter() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IEqualizerBand)->get_FrequencyCenter(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IEqualizerBand<D>::FrequencyCenter(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IEqualizerBand)->put_FrequencyCenter(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IEqualizerBand<D>::Gain() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IEqualizerBand)->get_Gain(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IEqualizerBand<D>::Gain(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IEqualizerBand)->put_Gain(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Audio::EqualizerBand>) consume_Windows_Media_Audio_IEqualizerEffectDefinition<D>::Bands() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IEqualizerEffectDefinition)->get_Bands(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Audio::EqualizerBand>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::EqualizerEffectDefinition) consume_Windows_Media_Audio_IEqualizerEffectDefinitionFactory<D>::Create(winrt::Windows::Media::Audio::AudioGraph const& audioGraph) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IEqualizerEffectDefinitionFactory)->Create(*(void**)(&audioGraph), &value));
        return winrt::Windows::Media::Audio::EqualizerEffectDefinition{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Media_Audio_IFrameInputNodeQuantumStartedEventArgs<D>::RequiredSamples() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IFrameInputNodeQuantumStartedEventArgs)->get_RequiredSamples(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_ILimiterEffectDefinition<D>::Release(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ILimiterEffectDefinition)->put_Release(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Audio_ILimiterEffectDefinition<D>::Release() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ILimiterEffectDefinition)->get_Release(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_ILimiterEffectDefinition<D>::Loudness(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ILimiterEffectDefinition)->put_Loudness(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Audio_ILimiterEffectDefinition<D>::Loudness() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ILimiterEffectDefinition)->get_Loudness(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::LimiterEffectDefinition) consume_Windows_Media_Audio_ILimiterEffectDefinitionFactory<D>::Create(winrt::Windows::Media::Audio::AudioGraph const& audioGraph) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ILimiterEffectDefinitionFactory)->Create(*(void**)(&audioGraph), &value));
        return winrt::Windows::Media::Audio::LimiterEffectDefinition{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IMediaSourceAudioInputNode<D>::PlaybackSpeedFactor(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IMediaSourceAudioInputNode)->put_PlaybackSpeedFactor(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IMediaSourceAudioInputNode<D>::PlaybackSpeedFactor() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IMediaSourceAudioInputNode)->get_PlaybackSpeedFactor(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Audio_IMediaSourceAudioInputNode<D>::Position() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IMediaSourceAudioInputNode)->get_Position(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IMediaSourceAudioInputNode<D>::Seek(winrt::Windows::Foundation::TimeSpan const& position) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IMediaSourceAudioInputNode)->Seek(impl::bind_in(position)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Media_Audio_IMediaSourceAudioInputNode<D>::StartTime() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IMediaSourceAudioInputNode)->get_StartTime(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IMediaSourceAudioInputNode<D>::StartTime(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IMediaSourceAudioInputNode)->put_StartTime(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) consume_Windows_Media_Audio_IMediaSourceAudioInputNode<D>::EndTime() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IMediaSourceAudioInputNode)->get_EndTime(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IMediaSourceAudioInputNode<D>::EndTime(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IMediaSourceAudioInputNode)->put_EndTime(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int32_t>) consume_Windows_Media_Audio_IMediaSourceAudioInputNode<D>::LoopCount() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IMediaSourceAudioInputNode)->get_LoopCount(&value));
        return winrt::Windows::Foundation::IReference<int32_t>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IMediaSourceAudioInputNode<D>::LoopCount(winrt::Windows::Foundation::IReference<int32_t> const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IMediaSourceAudioInputNode)->put_LoopCount(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Media_Audio_IMediaSourceAudioInputNode<D>::Duration() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IMediaSourceAudioInputNode)->get_Duration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Core::MediaSource) consume_Windows_Media_Audio_IMediaSourceAudioInputNode<D>::MediaSource() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IMediaSourceAudioInputNode)->get_MediaSource(&value));
        return winrt::Windows::Media::Core::MediaSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Audio_IMediaSourceAudioInputNode<D>::MediaSourceCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::MediaSourceAudioInputNode, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IMediaSourceAudioInputNode)->add_MediaSourceCompleted(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Audio_IMediaSourceAudioInputNode<D>::MediaSourceCompleted_revoker consume_Windows_Media_Audio_IMediaSourceAudioInputNode<D>::MediaSourceCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::MediaSourceAudioInputNode, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, MediaSourceCompleted_revoker>(this, MediaSourceCompleted(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IMediaSourceAudioInputNode<D>::MediaSourceCompleted(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IMediaSourceAudioInputNode)->remove_MediaSourceCompleted(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::WetDryMix(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->put_WetDryMix(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::WetDryMix() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->get_WetDryMix(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::ReflectionsDelay(uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->put_ReflectionsDelay(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::ReflectionsDelay() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->get_ReflectionsDelay(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::ReverbDelay(uint8_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->put_ReverbDelay(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::ReverbDelay() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->get_ReverbDelay(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::RearDelay(uint8_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->put_RearDelay(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::RearDelay() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->get_RearDelay(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::PositionLeft(uint8_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->put_PositionLeft(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::PositionLeft() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->get_PositionLeft(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::PositionRight(uint8_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->put_PositionRight(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::PositionRight() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->get_PositionRight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::PositionMatrixLeft(uint8_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->put_PositionMatrixLeft(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::PositionMatrixLeft() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->get_PositionMatrixLeft(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::PositionMatrixRight(uint8_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->put_PositionMatrixRight(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::PositionMatrixRight() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->get_PositionMatrixRight(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::EarlyDiffusion(uint8_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->put_EarlyDiffusion(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::EarlyDiffusion() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->get_EarlyDiffusion(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::LateDiffusion(uint8_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->put_LateDiffusion(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::LateDiffusion() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->get_LateDiffusion(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::LowEQGain(uint8_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->put_LowEQGain(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::LowEQGain() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->get_LowEQGain(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::LowEQCutoff(uint8_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->put_LowEQCutoff(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::LowEQCutoff() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->get_LowEQCutoff(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::HighEQGain(uint8_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->put_HighEQGain(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::HighEQGain() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->get_HighEQGain(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::HighEQCutoff(uint8_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->put_HighEQCutoff(value));
    }
    template <typename D> WINRT_IMPL_AUTO(uint8_t) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::HighEQCutoff() const
    {
        uint8_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->get_HighEQCutoff(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::RoomFilterFreq(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->put_RoomFilterFreq(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::RoomFilterFreq() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->get_RoomFilterFreq(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::RoomFilterMain(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->put_RoomFilterMain(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::RoomFilterMain() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->get_RoomFilterMain(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::RoomFilterHF(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->put_RoomFilterHF(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::RoomFilterHF() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->get_RoomFilterHF(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::ReflectionsGain(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->put_ReflectionsGain(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::ReflectionsGain() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->get_ReflectionsGain(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::ReverbGain(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->put_ReverbGain(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::ReverbGain() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->get_ReverbGain(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::DecayTime(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->put_DecayTime(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::DecayTime() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->get_DecayTime(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::Density(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->put_Density(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::Density() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->get_Density(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::RoomSize(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->put_RoomSize(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::RoomSize() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->get_RoomSize(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::DisableLateField(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->put_DisableLateField(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Audio_IReverbEffectDefinition<D>::DisableLateField() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinition)->get_DisableLateField(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::ReverbEffectDefinition) consume_Windows_Media_Audio_IReverbEffectDefinitionFactory<D>::Create(winrt::Windows::Media::Audio::AudioGraph const& audioGraph) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::IReverbEffectDefinitionFactory)->Create(*(void**)(&audioGraph), &value));
        return winrt::Windows::Media::Audio::ReverbEffectDefinition{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::SetDefaultSpatialAudioFormatStatus) consume_Windows_Media_Audio_ISetDefaultSpatialAudioFormatResult<D>::Status() const
    {
        winrt::Windows::Media::Audio::SetDefaultSpatialAudioFormatStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ISetDefaultSpatialAudioFormatResult)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Audio_ISpatialAudioDeviceConfiguration<D>::DeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ISpatialAudioDeviceConfiguration)->get_DeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Audio_ISpatialAudioDeviceConfiguration<D>::IsSpatialAudioSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ISpatialAudioDeviceConfiguration)->get_IsSpatialAudioSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Audio_ISpatialAudioDeviceConfiguration<D>::IsSpatialAudioFormatSupported(param::hstring const& subtype) const
    {
        bool result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ISpatialAudioDeviceConfiguration)->IsSpatialAudioFormatSupported(*(void**)(&subtype), &result));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Audio_ISpatialAudioDeviceConfiguration<D>::ActiveSpatialAudioFormat() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ISpatialAudioDeviceConfiguration)->get_ActiveSpatialAudioFormat(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Audio_ISpatialAudioDeviceConfiguration<D>::DefaultSpatialAudioFormat() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ISpatialAudioDeviceConfiguration)->get_DefaultSpatialAudioFormat(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::SetDefaultSpatialAudioFormatResult>) consume_Windows_Media_Audio_ISpatialAudioDeviceConfiguration<D>::SetDefaultSpatialAudioFormatAsync(param::hstring const& subtype) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ISpatialAudioDeviceConfiguration)->SetDefaultSpatialAudioFormatAsync(*(void**)(&subtype), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::SetDefaultSpatialAudioFormatResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Audio_ISpatialAudioDeviceConfiguration<D>::ConfigurationChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::SpatialAudioDeviceConfiguration, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ISpatialAudioDeviceConfiguration)->add_ConfigurationChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Audio_ISpatialAudioDeviceConfiguration<D>::ConfigurationChanged_revoker consume_Windows_Media_Audio_ISpatialAudioDeviceConfiguration<D>::ConfigurationChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::SpatialAudioDeviceConfiguration, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, ConfigurationChanged_revoker>(this, ConfigurationChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_ISpatialAudioDeviceConfiguration<D>::ConfigurationChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ISpatialAudioDeviceConfiguration)->remove_ConfigurationChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::SpatialAudioDeviceConfiguration) consume_Windows_Media_Audio_ISpatialAudioDeviceConfigurationStatics<D>::GetForDeviceId(param::hstring const& deviceId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ISpatialAudioDeviceConfigurationStatics)->GetForDeviceId(*(void**)(&deviceId), &result));
        return winrt::Windows::Media::Audio::SpatialAudioDeviceConfiguration{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Audio_ISpatialAudioFormatConfiguration<D>::ReportLicenseChangedAsync(param::hstring const& subtype) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ISpatialAudioFormatConfiguration)->ReportLicenseChangedAsync(*(void**)(&subtype), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Media_Audio_ISpatialAudioFormatConfiguration<D>::ReportConfigurationChangedAsync(param::hstring const& subtype) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ISpatialAudioFormatConfiguration)->ReportConfigurationChangedAsync(*(void**)(&subtype), &operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::MixedRealitySpatialAudioFormatPolicy) consume_Windows_Media_Audio_ISpatialAudioFormatConfiguration<D>::MixedRealityExclusiveModePolicy() const
    {
        winrt::Windows::Media::Audio::MixedRealitySpatialAudioFormatPolicy value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ISpatialAudioFormatConfiguration)->get_MixedRealityExclusiveModePolicy(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Audio_ISpatialAudioFormatConfiguration<D>::MixedRealityExclusiveModePolicy(winrt::Windows::Media::Audio::MixedRealitySpatialAudioFormatPolicy const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ISpatialAudioFormatConfiguration)->put_MixedRealityExclusiveModePolicy(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Audio::SpatialAudioFormatConfiguration) consume_Windows_Media_Audio_ISpatialAudioFormatConfigurationStatics<D>::GetDefault() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ISpatialAudioFormatConfigurationStatics)->GetDefault(&result));
        return winrt::Windows::Media::Audio::SpatialAudioFormatConfiguration{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Audio_ISpatialAudioFormatSubtypeStatics<D>::WindowsSonic() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ISpatialAudioFormatSubtypeStatics)->get_WindowsSonic(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Audio_ISpatialAudioFormatSubtypeStatics<D>::DolbyAtmosForHeadphones() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ISpatialAudioFormatSubtypeStatics)->get_DolbyAtmosForHeadphones(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Audio_ISpatialAudioFormatSubtypeStatics<D>::DolbyAtmosForHomeTheater() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ISpatialAudioFormatSubtypeStatics)->get_DolbyAtmosForHomeTheater(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Audio_ISpatialAudioFormatSubtypeStatics<D>::DolbyAtmosForSpeakers() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ISpatialAudioFormatSubtypeStatics)->get_DolbyAtmosForSpeakers(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Audio_ISpatialAudioFormatSubtypeStatics<D>::DTSHeadphoneX() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ISpatialAudioFormatSubtypeStatics)->get_DTSHeadphoneX(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Audio_ISpatialAudioFormatSubtypeStatics<D>::DTSXUltra() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ISpatialAudioFormatSubtypeStatics)->get_DTSXUltra(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Audio_ISpatialAudioFormatSubtypeStatics2<D>::DTSXForHomeTheater() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Audio::ISpatialAudioFormatSubtypeStatics2)->get_DTSXForHomeTheater(&value));
        return hstring{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioDeviceInputNode> : produce_base<D, winrt::Windows::Media::Audio::IAudioDeviceInputNode>
    {
        int32_t __stdcall get_Device(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DeviceInformation>(this->shim().Device());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioDeviceOutputNode> : produce_base<D, winrt::Windows::Media::Audio::IAudioDeviceOutputNode>
    {
        int32_t __stdcall get_Device(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DeviceInformation>(this->shim().Device());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioFileInputNode> : produce_base<D, winrt::Windows::Media::Audio::IAudioFileInputNode>
    {
        int32_t __stdcall put_PlaybackSpeedFactor(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PlaybackSpeedFactor(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PlaybackSpeedFactor(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().PlaybackSpeedFactor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Position(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Seek(int64_t position) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Seek(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&position));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StartTime(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().StartTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StartTime(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartTime(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EndTime(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().EndTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EndTime(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EndTime(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LoopCount(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().LoopCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LoopCount(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LoopCount(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
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
        int32_t __stdcall get_SourceFile(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::StorageFile>(this->shim().SourceFile());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_FileCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().FileCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::AudioFileInputNode, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_FileCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FileCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioFileOutputNode> : produce_base<D, winrt::Windows::Media::Audio::IAudioFileOutputNode>
    {
        int32_t __stdcall get_File(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::IStorageFile>(this->shim().File());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FileEncodingProfile(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::MediaEncodingProfile>(this->shim().FileEncodingProfile());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FinalizeAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Transcoding::TranscodeFailureReason>>(this->shim().FinalizeAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioFrameCompletedEventArgs> : produce_base<D, winrt::Windows::Media::Audio::IAudioFrameCompletedEventArgs>
    {
        int32_t __stdcall get_Frame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::AudioFrame>(this->shim().Frame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioFrameInputNode> : produce_base<D, winrt::Windows::Media::Audio::IAudioFrameInputNode>
    {
        int32_t __stdcall put_PlaybackSpeedFactor(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PlaybackSpeedFactor(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PlaybackSpeedFactor(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().PlaybackSpeedFactor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddFrame(void* frame) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddFrame(*reinterpret_cast<winrt::Windows::Media::AudioFrame const*>(&frame));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DiscardQueuedFrames() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DiscardQueuedFrames();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_QueuedSampleCount(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().QueuedSampleCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_AudioFrameCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AudioFrameCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::AudioFrameInputNode, winrt::Windows::Media::Audio::AudioFrameCompletedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AudioFrameCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AudioFrameCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_QuantumStarted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().QuantumStarted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::AudioFrameInputNode, winrt::Windows::Media::Audio::FrameInputNodeQuantumStartedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_QuantumStarted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().QuantumStarted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioFrameOutputNode> : produce_base<D, winrt::Windows::Media::Audio::IAudioFrameOutputNode>
    {
        int32_t __stdcall GetFrame(void** audioFrame) noexcept final try
        {
            clear_abi(audioFrame);
            typename D::abi_guard guard(this->shim());
            *audioFrame = detach_from<winrt::Windows::Media::AudioFrame>(this->shim().GetFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioGraph> : produce_base<D, winrt::Windows::Media::Audio::IAudioGraph>
    {
        int32_t __stdcall CreateFrameInputNode(void** frameInputNode) noexcept final try
        {
            clear_abi(frameInputNode);
            typename D::abi_guard guard(this->shim());
            *frameInputNode = detach_from<winrt::Windows::Media::Audio::AudioFrameInputNode>(this->shim().CreateFrameInputNode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFrameInputNodeWithFormat(void* encodingProperties, void** frameInputNode) noexcept final try
        {
            clear_abi(frameInputNode);
            typename D::abi_guard guard(this->shim());
            *frameInputNode = detach_from<winrt::Windows::Media::Audio::AudioFrameInputNode>(this->shim().CreateFrameInputNode(*reinterpret_cast<winrt::Windows::Media::MediaProperties::AudioEncodingProperties const*>(&encodingProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateDeviceInputNodeAsync(int32_t category, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioDeviceInputNodeResult>>(this->shim().CreateDeviceInputNodeAsync(*reinterpret_cast<winrt::Windows::Media::Capture::MediaCategory const*>(&category)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateDeviceInputNodeWithFormatAsync(int32_t category, void* encodingProperties, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioDeviceInputNodeResult>>(this->shim().CreateDeviceInputNodeAsync(*reinterpret_cast<winrt::Windows::Media::Capture::MediaCategory const*>(&category), *reinterpret_cast<winrt::Windows::Media::MediaProperties::AudioEncodingProperties const*>(&encodingProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateDeviceInputNodeWithFormatOnDeviceAsync(int32_t category, void* encodingProperties, void* device, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioDeviceInputNodeResult>>(this->shim().CreateDeviceInputNodeAsync(*reinterpret_cast<winrt::Windows::Media::Capture::MediaCategory const*>(&category), *reinterpret_cast<winrt::Windows::Media::MediaProperties::AudioEncodingProperties const*>(&encodingProperties), *reinterpret_cast<winrt::Windows::Devices::Enumeration::DeviceInformation const*>(&device)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFrameOutputNode(void** frameOutputNode) noexcept final try
        {
            clear_abi(frameOutputNode);
            typename D::abi_guard guard(this->shim());
            *frameOutputNode = detach_from<winrt::Windows::Media::Audio::AudioFrameOutputNode>(this->shim().CreateFrameOutputNode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFrameOutputNodeWithFormat(void* encodingProperties, void** frameOutputNode) noexcept final try
        {
            clear_abi(frameOutputNode);
            typename D::abi_guard guard(this->shim());
            *frameOutputNode = detach_from<winrt::Windows::Media::Audio::AudioFrameOutputNode>(this->shim().CreateFrameOutputNode(*reinterpret_cast<winrt::Windows::Media::MediaProperties::AudioEncodingProperties const*>(&encodingProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateDeviceOutputNodeAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioDeviceOutputNodeResult>>(this->shim().CreateDeviceOutputNodeAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFileInputNodeAsync(void* file, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioFileInputNodeResult>>(this->shim().CreateFileInputNodeAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFileOutputNodeAsync(void* file, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioFileOutputNodeResult>>(this->shim().CreateFileOutputNodeAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFileOutputNodeWithFileProfileAsync(void* file, void* fileEncodingProfile, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioFileOutputNodeResult>>(this->shim().CreateFileOutputNodeAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<winrt::Windows::Media::MediaProperties::MediaEncodingProfile const*>(&fileEncodingProfile)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateSubmixNode(void** submixNode) noexcept final try
        {
            clear_abi(submixNode);
            typename D::abi_guard guard(this->shim());
            *submixNode = detach_from<winrt::Windows::Media::Audio::AudioSubmixNode>(this->shim().CreateSubmixNode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateSubmixNodeWithFormat(void* encodingProperties, void** submixNode) noexcept final try
        {
            clear_abi(submixNode);
            typename D::abi_guard guard(this->shim());
            *submixNode = detach_from<winrt::Windows::Media::Audio::AudioSubmixNode>(this->shim().CreateSubmixNode(*reinterpret_cast<winrt::Windows::Media::MediaProperties::AudioEncodingProperties const*>(&encodingProperties)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Start() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Start();
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
        int32_t __stdcall ResetAllNodes() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ResetAllNodes();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_QuantumStarted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().QuantumStarted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::AudioGraph, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_QuantumStarted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().QuantumStarted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_QuantumProcessed(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().QuantumProcessed(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::AudioGraph, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_QuantumProcessed(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().QuantumProcessed(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_UnrecoverableErrorOccurred(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().UnrecoverableErrorOccurred(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::AudioGraph, winrt::Windows::Media::Audio::AudioGraphUnrecoverableErrorOccurredEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_UnrecoverableErrorOccurred(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UnrecoverableErrorOccurred(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_CompletedQuantumCount(uint64_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint64_t>(this->shim().CompletedQuantumCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EncodingProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().EncodingProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LatencyInSamples(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().LatencyInSamples());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PrimaryRenderDevice(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DeviceInformation>(this->shim().PrimaryRenderDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RenderDeviceAudioProcessing(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::AudioProcessing>(this->shim().RenderDeviceAudioProcessing());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SamplesPerQuantum(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().SamplesPerQuantum());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioGraph2> : produce_base<D, winrt::Windows::Media::Audio::IAudioGraph2>
    {
        int32_t __stdcall CreateFrameInputNodeWithFormatAndEmitter(void* encodingProperties, void* emitter, void** frameInputNode) noexcept final try
        {
            clear_abi(frameInputNode);
            typename D::abi_guard guard(this->shim());
            *frameInputNode = detach_from<winrt::Windows::Media::Audio::AudioFrameInputNode>(this->shim().CreateFrameInputNode(*reinterpret_cast<winrt::Windows::Media::MediaProperties::AudioEncodingProperties const*>(&encodingProperties), *reinterpret_cast<winrt::Windows::Media::Audio::AudioNodeEmitter const*>(&emitter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateDeviceInputNodeWithFormatAndEmitterOnDeviceAsync(int32_t category, void* encodingProperties, void* device, void* emitter, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioDeviceInputNodeResult>>(this->shim().CreateDeviceInputNodeAsync(*reinterpret_cast<winrt::Windows::Media::Capture::MediaCategory const*>(&category), *reinterpret_cast<winrt::Windows::Media::MediaProperties::AudioEncodingProperties const*>(&encodingProperties), *reinterpret_cast<winrt::Windows::Devices::Enumeration::DeviceInformation const*>(&device), *reinterpret_cast<winrt::Windows::Media::Audio::AudioNodeEmitter const*>(&emitter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFileInputNodeWithEmitterAsync(void* file, void* emitter, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioFileInputNodeResult>>(this->shim().CreateFileInputNodeAsync(*reinterpret_cast<winrt::Windows::Storage::IStorageFile const*>(&file), *reinterpret_cast<winrt::Windows::Media::Audio::AudioNodeEmitter const*>(&emitter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateSubmixNodeWithFormatAndEmitter(void* encodingProperties, void* emitter, void** submixNode) noexcept final try
        {
            clear_abi(submixNode);
            typename D::abi_guard guard(this->shim());
            *submixNode = detach_from<winrt::Windows::Media::Audio::AudioSubmixNode>(this->shim().CreateSubmixNode(*reinterpret_cast<winrt::Windows::Media::MediaProperties::AudioEncodingProperties const*>(&encodingProperties), *reinterpret_cast<winrt::Windows::Media::Audio::AudioNodeEmitter const*>(&emitter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateBatchUpdater(void** updater) noexcept final try
        {
            clear_abi(updater);
            typename D::abi_guard guard(this->shim());
            *updater = detach_from<winrt::Windows::Media::Audio::AudioGraphBatchUpdater>(this->shim().CreateBatchUpdater());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioGraph3> : produce_base<D, winrt::Windows::Media::Audio::IAudioGraph3>
    {
        int32_t __stdcall CreateMediaSourceAudioInputNodeAsync(void* mediaSource, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateMediaSourceAudioInputNodeResult>>(this->shim().CreateMediaSourceAudioInputNodeAsync(*reinterpret_cast<winrt::Windows::Media::Core::MediaSource const*>(&mediaSource)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateMediaSourceAudioInputNodeWithEmitterAsync(void* mediaSource, void* emitter, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateMediaSourceAudioInputNodeResult>>(this->shim().CreateMediaSourceAudioInputNodeAsync(*reinterpret_cast<winrt::Windows::Media::Core::MediaSource const*>(&mediaSource), *reinterpret_cast<winrt::Windows::Media::Audio::AudioNodeEmitter const*>(&emitter)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioGraphConnection> : produce_base<D, winrt::Windows::Media::Audio::IAudioGraphConnection>
    {
        int32_t __stdcall get_Destination(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::IAudioNode>(this->shim().Destination());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Gain(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Gain(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Gain(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Gain());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioGraphSettings> : produce_base<D, winrt::Windows::Media::Audio::IAudioGraphSettings>
    {
        int32_t __stdcall get_EncodingProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().EncodingProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EncodingProperties(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EncodingProperties(*reinterpret_cast<winrt::Windows::Media::MediaProperties::AudioEncodingProperties const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PrimaryRenderDevice(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Enumeration::DeviceInformation>(this->shim().PrimaryRenderDevice());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PrimaryRenderDevice(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PrimaryRenderDevice(*reinterpret_cast<winrt::Windows::Devices::Enumeration::DeviceInformation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_QuantumSizeSelectionMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::QuantumSizeSelectionMode>(this->shim().QuantumSizeSelectionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_QuantumSizeSelectionMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().QuantumSizeSelectionMode(*reinterpret_cast<winrt::Windows::Media::Audio::QuantumSizeSelectionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DesiredSamplesPerQuantum(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().DesiredSamplesPerQuantum());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DesiredSamplesPerQuantum(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DesiredSamplesPerQuantum(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioRenderCategory(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Render::AudioRenderCategory>(this->shim().AudioRenderCategory());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AudioRenderCategory(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AudioRenderCategory(*reinterpret_cast<winrt::Windows::Media::Render::AudioRenderCategory const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DesiredRenderDeviceAudioProcessing(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::AudioProcessing>(this->shim().DesiredRenderDeviceAudioProcessing());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DesiredRenderDeviceAudioProcessing(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DesiredRenderDeviceAudioProcessing(*reinterpret_cast<winrt::Windows::Media::AudioProcessing const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioGraphSettings2> : produce_base<D, winrt::Windows::Media::Audio::IAudioGraphSettings2>
    {
        int32_t __stdcall put_MaxPlaybackSpeedFactor(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MaxPlaybackSpeedFactor(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxPlaybackSpeedFactor(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().MaxPlaybackSpeedFactor());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioGraphSettingsFactory> : produce_base<D, winrt::Windows::Media::Audio::IAudioGraphSettingsFactory>
    {
        int32_t __stdcall Create(int32_t audioRenderCategory, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::AudioGraphSettings>(this->shim().Create(*reinterpret_cast<winrt::Windows::Media::Render::AudioRenderCategory const*>(&audioRenderCategory)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioGraphStatics> : produce_base<D, winrt::Windows::Media::Audio::IAudioGraphStatics>
    {
        int32_t __stdcall CreateAsync(void* settings, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::CreateAudioGraphResult>>(this->shim().CreateAsync(*reinterpret_cast<winrt::Windows::Media::Audio::AudioGraphSettings const*>(&settings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioGraphUnrecoverableErrorOccurredEventArgs> : produce_base<D, winrt::Windows::Media::Audio::IAudioGraphUnrecoverableErrorOccurredEventArgs>
    {
        int32_t __stdcall get_Error(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::AudioGraphUnrecoverableError>(this->shim().Error());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioInputNode> : produce_base<D, winrt::Windows::Media::Audio::IAudioInputNode>
    {
        int32_t __stdcall get_OutgoingConnections(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Audio::AudioGraphConnection>>(this->shim().OutgoingConnections());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddOutgoingConnection(void* destination) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddOutgoingConnection(*reinterpret_cast<winrt::Windows::Media::Audio::IAudioNode const*>(&destination));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddOutgoingConnectionWithGain(void* destination, double gain) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddOutgoingConnection(*reinterpret_cast<winrt::Windows::Media::Audio::IAudioNode const*>(&destination), gain);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RemoveOutgoingConnection(void* destination) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RemoveOutgoingConnection(*reinterpret_cast<winrt::Windows::Media::Audio::IAudioNode const*>(&destination));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioInputNode2> : produce_base<D, winrt::Windows::Media::Audio::IAudioInputNode2>
    {
        int32_t __stdcall get_Emitter(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::AudioNodeEmitter>(this->shim().Emitter());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioNode> : produce_base<D, winrt::Windows::Media::Audio::IAudioNode>
    {
        int32_t __stdcall get_EffectDefinitions(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Media::Effects::IAudioEffectDefinition>>(this->shim().EffectDefinitions());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OutgoingGain(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OutgoingGain(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OutgoingGain(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().OutgoingGain());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EncodingProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::AudioEncodingProperties>(this->shim().EncodingProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ConsumeInput(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ConsumeInput());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ConsumeInput(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ConsumeInput(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Start() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Start();
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
        int32_t __stdcall Reset() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Reset();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DisableEffectsByDefinition(void* definition) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisableEffectsByDefinition(*reinterpret_cast<winrt::Windows::Media::Effects::IAudioEffectDefinition const*>(&definition));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall EnableEffectsByDefinition(void* definition) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EnableEffectsByDefinition(*reinterpret_cast<winrt::Windows::Media::Effects::IAudioEffectDefinition const*>(&definition));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioNodeEmitter> : produce_base<D, winrt::Windows::Media::Audio::IAudioNodeEmitter>
    {
        int32_t __stdcall get_Position(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Position(winrt::Windows::Foundation::Numerics::float3 value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Position(*reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Direction(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().Direction());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Direction(winrt::Windows::Foundation::Numerics::float3 value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Direction(*reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Shape(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::AudioNodeEmitterShape>(this->shim().Shape());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DecayModel(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::AudioNodeEmitterDecayModel>(this->shim().DecayModel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Gain(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Gain());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Gain(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Gain(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DistanceScale(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().DistanceScale());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DistanceScale(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DistanceScale(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DopplerScale(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().DopplerScale());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DopplerScale(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DopplerScale(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DopplerVelocity(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().DopplerVelocity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DopplerVelocity(winrt::Windows::Foundation::Numerics::float3 value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DopplerVelocity(*reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDopplerDisabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDopplerDisabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioNodeEmitter2> : produce_base<D, winrt::Windows::Media::Audio::IAudioNodeEmitter2>
    {
        int32_t __stdcall get_SpatialAudioModel(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::SpatialAudioModel>(this->shim().SpatialAudioModel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SpatialAudioModel(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SpatialAudioModel(*reinterpret_cast<winrt::Windows::Media::Audio::SpatialAudioModel const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioNodeEmitterConeProperties> : produce_base<D, winrt::Windows::Media::Audio::IAudioNodeEmitterConeProperties>
    {
        int32_t __stdcall get_InnerAngle(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().InnerAngle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OuterAngle(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().OuterAngle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OuterAngleGain(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().OuterAngleGain());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioNodeEmitterDecayModel> : produce_base<D, winrt::Windows::Media::Audio::IAudioNodeEmitterDecayModel>
    {
        int32_t __stdcall get_Kind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::AudioNodeEmitterDecayKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MinGain(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().MinGain());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MaxGain(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().MaxGain());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NaturalProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::AudioNodeEmitterNaturalDecayModelProperties>(this->shim().NaturalProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioNodeEmitterDecayModelStatics> : produce_base<D, winrt::Windows::Media::Audio::IAudioNodeEmitterDecayModelStatics>
    {
        int32_t __stdcall CreateNatural(double minGain, double maxGain, double unityGainDistance, double cutoffDistance, void** decayModel) noexcept final try
        {
            clear_abi(decayModel);
            typename D::abi_guard guard(this->shim());
            *decayModel = detach_from<winrt::Windows::Media::Audio::AudioNodeEmitterDecayModel>(this->shim().CreateNatural(minGain, maxGain, unityGainDistance, cutoffDistance));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateCustom(double minGain, double maxGain, void** decayModel) noexcept final try
        {
            clear_abi(decayModel);
            typename D::abi_guard guard(this->shim());
            *decayModel = detach_from<winrt::Windows::Media::Audio::AudioNodeEmitterDecayModel>(this->shim().CreateCustom(minGain, maxGain));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioNodeEmitterFactory> : produce_base<D, winrt::Windows::Media::Audio::IAudioNodeEmitterFactory>
    {
        int32_t __stdcall CreateAudioNodeEmitter(void* shape, void* decayModel, uint32_t settings, void** emitter) noexcept final try
        {
            clear_abi(emitter);
            typename D::abi_guard guard(this->shim());
            *emitter = detach_from<winrt::Windows::Media::Audio::AudioNodeEmitter>(this->shim().CreateAudioNodeEmitter(*reinterpret_cast<winrt::Windows::Media::Audio::AudioNodeEmitterShape const*>(&shape), *reinterpret_cast<winrt::Windows::Media::Audio::AudioNodeEmitterDecayModel const*>(&decayModel), *reinterpret_cast<winrt::Windows::Media::Audio::AudioNodeEmitterSettings const*>(&settings)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioNodeEmitterNaturalDecayModelProperties> : produce_base<D, winrt::Windows::Media::Audio::IAudioNodeEmitterNaturalDecayModelProperties>
    {
        int32_t __stdcall get_UnityGainDistance(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().UnityGainDistance());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CutoffDistance(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().CutoffDistance());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioNodeEmitterShape> : produce_base<D, winrt::Windows::Media::Audio::IAudioNodeEmitterShape>
    {
        int32_t __stdcall get_Kind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::AudioNodeEmitterShapeKind>(this->shim().Kind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ConeProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::AudioNodeEmitterConeProperties>(this->shim().ConeProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioNodeEmitterShapeStatics> : produce_base<D, winrt::Windows::Media::Audio::IAudioNodeEmitterShapeStatics>
    {
        int32_t __stdcall CreateCone(double innerAngle, double outerAngle, double outerAngleGain, void** shape) noexcept final try
        {
            clear_abi(shape);
            typename D::abi_guard guard(this->shim());
            *shape = detach_from<winrt::Windows::Media::Audio::AudioNodeEmitterShape>(this->shim().CreateCone(innerAngle, outerAngle, outerAngleGain));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateOmnidirectional(void** shape) noexcept final try
        {
            clear_abi(shape);
            typename D::abi_guard guard(this->shim());
            *shape = detach_from<winrt::Windows::Media::Audio::AudioNodeEmitterShape>(this->shim().CreateOmnidirectional());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioNodeListener> : produce_base<D, winrt::Windows::Media::Audio::IAudioNodeListener>
    {
        int32_t __stdcall get_Position(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Position(winrt::Windows::Foundation::Numerics::float3 value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Position(*reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Orientation(winrt::Windows::Foundation::Numerics::quaternion* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::quaternion>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::quaternion>(this->shim().Orientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Orientation(winrt::Windows::Foundation::Numerics::quaternion value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Orientation(*reinterpret_cast<winrt::Windows::Foundation::Numerics::quaternion const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SpeedOfSound(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().SpeedOfSound());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SpeedOfSound(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SpeedOfSound(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DopplerVelocity(winrt::Windows::Foundation::Numerics::float3* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::float3>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::float3>(this->shim().DopplerVelocity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DopplerVelocity(winrt::Windows::Foundation::Numerics::float3 value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DopplerVelocity(*reinterpret_cast<winrt::Windows::Foundation::Numerics::float3 const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioNodeWithListener> : produce_base<D, winrt::Windows::Media::Audio::IAudioNodeWithListener>
    {
        int32_t __stdcall put_Listener(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Listener(*reinterpret_cast<winrt::Windows::Media::Audio::AudioNodeListener const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Listener(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::AudioNodeListener>(this->shim().Listener());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioPlaybackConnection> : produce_base<D, winrt::Windows::Media::Audio::IAudioPlaybackConnection>
    {
        int32_t __stdcall Start() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().StartAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_State(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::AudioPlaybackConnectionState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Open(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Audio::AudioPlaybackConnectionOpenResult>(this->shim().Open());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall OpenAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::AudioPlaybackConnectionOpenResult>>(this->shim().OpenAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_StateChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().StateChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::AudioPlaybackConnection, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_StateChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StateChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioPlaybackConnectionOpenResult> : produce_base<D, winrt::Windows::Media::Audio::IAudioPlaybackConnectionOpenResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::AudioPlaybackConnectionOpenResultStatus>(this->shim().Status());
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
    struct produce<D, winrt::Windows::Media::Audio::IAudioPlaybackConnectionStatics> : produce_base<D, winrt::Windows::Media::Audio::IAudioPlaybackConnectionStatics>
    {
        int32_t __stdcall GetDeviceSelector(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryCreateFromId(void* id, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Audio::AudioPlaybackConnection>(this->shim().TryCreateFromId(*reinterpret_cast<hstring const*>(&id)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioStateMonitor> : produce_base<D, winrt::Windows::Media::Audio::IAudioStateMonitor>
    {
        int32_t __stdcall add_SoundLevelChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SoundLevelChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::AudioStateMonitor, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SoundLevelChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SoundLevelChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall get_SoundLevel(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SoundLevel>(this->shim().SoundLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IAudioStateMonitorStatics> : produce_base<D, winrt::Windows::Media::Audio::IAudioStateMonitorStatics>
    {
        int32_t __stdcall CreateForRenderMonitoring(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Audio::AudioStateMonitor>(this->shim().CreateForRenderMonitoring());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateForRenderMonitoringWithCategory(int32_t category, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Audio::AudioStateMonitor>(this->shim().CreateForRenderMonitoring(*reinterpret_cast<winrt::Windows::Media::Render::AudioRenderCategory const*>(&category)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateForRenderMonitoringWithCategoryAndDeviceRole(int32_t category, int32_t role, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Audio::AudioStateMonitor>(this->shim().CreateForRenderMonitoring(*reinterpret_cast<winrt::Windows::Media::Render::AudioRenderCategory const*>(&category), *reinterpret_cast<winrt::Windows::Media::Devices::AudioDeviceRole const*>(&role)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateForRenderMonitoringWithCategoryAndDeviceId(int32_t category, void* deviceId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Audio::AudioStateMonitor>(this->shim().CreateForRenderMonitoringWithCategoryAndDeviceId(*reinterpret_cast<winrt::Windows::Media::Render::AudioRenderCategory const*>(&category), *reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateForCaptureMonitoring(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Audio::AudioStateMonitor>(this->shim().CreateForCaptureMonitoring());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateForCaptureMonitoringWithCategory(int32_t category, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Audio::AudioStateMonitor>(this->shim().CreateForCaptureMonitoring(*reinterpret_cast<winrt::Windows::Media::Capture::MediaCategory const*>(&category)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateForCaptureMonitoringWithCategoryAndDeviceRole(int32_t category, int32_t role, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Audio::AudioStateMonitor>(this->shim().CreateForCaptureMonitoring(*reinterpret_cast<winrt::Windows::Media::Capture::MediaCategory const*>(&category), *reinterpret_cast<winrt::Windows::Media::Devices::AudioDeviceRole const*>(&role)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateForCaptureMonitoringWithCategoryAndDeviceId(int32_t category, void* deviceId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Audio::AudioStateMonitor>(this->shim().CreateForCaptureMonitoringWithCategoryAndDeviceId(*reinterpret_cast<winrt::Windows::Media::Capture::MediaCategory const*>(&category), *reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::ICreateAudioDeviceInputNodeResult> : produce_base<D, winrt::Windows::Media::Audio::ICreateAudioDeviceInputNodeResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::AudioDeviceNodeCreationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeviceInputNode(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::AudioDeviceInputNode>(this->shim().DeviceInputNode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::ICreateAudioDeviceInputNodeResult2> : produce_base<D, winrt::Windows::Media::Audio::ICreateAudioDeviceInputNodeResult2>
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
    struct produce<D, winrt::Windows::Media::Audio::ICreateAudioDeviceOutputNodeResult> : produce_base<D, winrt::Windows::Media::Audio::ICreateAudioDeviceOutputNodeResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::AudioDeviceNodeCreationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DeviceOutputNode(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::AudioDeviceOutputNode>(this->shim().DeviceOutputNode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::ICreateAudioDeviceOutputNodeResult2> : produce_base<D, winrt::Windows::Media::Audio::ICreateAudioDeviceOutputNodeResult2>
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
    struct produce<D, winrt::Windows::Media::Audio::ICreateAudioFileInputNodeResult> : produce_base<D, winrt::Windows::Media::Audio::ICreateAudioFileInputNodeResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::AudioFileNodeCreationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FileInputNode(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::AudioFileInputNode>(this->shim().FileInputNode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::ICreateAudioFileInputNodeResult2> : produce_base<D, winrt::Windows::Media::Audio::ICreateAudioFileInputNodeResult2>
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
    struct produce<D, winrt::Windows::Media::Audio::ICreateAudioFileOutputNodeResult> : produce_base<D, winrt::Windows::Media::Audio::ICreateAudioFileOutputNodeResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::AudioFileNodeCreationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FileOutputNode(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::AudioFileOutputNode>(this->shim().FileOutputNode());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::ICreateAudioFileOutputNodeResult2> : produce_base<D, winrt::Windows::Media::Audio::ICreateAudioFileOutputNodeResult2>
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
    struct produce<D, winrt::Windows::Media::Audio::ICreateAudioGraphResult> : produce_base<D, winrt::Windows::Media::Audio::ICreateAudioGraphResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::AudioGraphCreationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Graph(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::AudioGraph>(this->shim().Graph());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::ICreateAudioGraphResult2> : produce_base<D, winrt::Windows::Media::Audio::ICreateAudioGraphResult2>
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
    struct produce<D, winrt::Windows::Media::Audio::ICreateMediaSourceAudioInputNodeResult> : produce_base<D, winrt::Windows::Media::Audio::ICreateMediaSourceAudioInputNodeResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::MediaSourceAudioInputNodeCreationStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Node(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::MediaSourceAudioInputNode>(this->shim().Node());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::ICreateMediaSourceAudioInputNodeResult2> : produce_base<D, winrt::Windows::Media::Audio::ICreateMediaSourceAudioInputNodeResult2>
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
    struct produce<D, winrt::Windows::Media::Audio::IEchoEffectDefinition> : produce_base<D, winrt::Windows::Media::Audio::IEchoEffectDefinition>
    {
        int32_t __stdcall put_WetDryMix(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WetDryMix(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WetDryMix(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().WetDryMix());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Feedback(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Feedback(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Feedback(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Feedback());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Delay(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Delay(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Delay(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Delay());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IEchoEffectDefinitionFactory> : produce_base<D, winrt::Windows::Media::Audio::IEchoEffectDefinitionFactory>
    {
        int32_t __stdcall Create(void* audioGraph, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::EchoEffectDefinition>(this->shim().Create(*reinterpret_cast<winrt::Windows::Media::Audio::AudioGraph const*>(&audioGraph)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IEqualizerBand> : produce_base<D, winrt::Windows::Media::Audio::IEqualizerBand>
    {
        int32_t __stdcall get_Bandwidth(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Bandwidth());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Bandwidth(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Bandwidth(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FrequencyCenter(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().FrequencyCenter());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FrequencyCenter(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FrequencyCenter(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Gain(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Gain());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Gain(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Gain(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IEqualizerEffectDefinition> : produce_base<D, winrt::Windows::Media::Audio::IEqualizerEffectDefinition>
    {
        int32_t __stdcall get_Bands(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Audio::EqualizerBand>>(this->shim().Bands());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IEqualizerEffectDefinitionFactory> : produce_base<D, winrt::Windows::Media::Audio::IEqualizerEffectDefinitionFactory>
    {
        int32_t __stdcall Create(void* audioGraph, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::EqualizerEffectDefinition>(this->shim().Create(*reinterpret_cast<winrt::Windows::Media::Audio::AudioGraph const*>(&audioGraph)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IFrameInputNodeQuantumStartedEventArgs> : produce_base<D, winrt::Windows::Media::Audio::IFrameInputNodeQuantumStartedEventArgs>
    {
        int32_t __stdcall get_RequiredSamples(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().RequiredSamples());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::ILimiterEffectDefinition> : produce_base<D, winrt::Windows::Media::Audio::ILimiterEffectDefinition>
    {
        int32_t __stdcall put_Release(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Release(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Release(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Release());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Loudness(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Loudness(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Loudness(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Loudness());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::ILimiterEffectDefinitionFactory> : produce_base<D, winrt::Windows::Media::Audio::ILimiterEffectDefinitionFactory>
    {
        int32_t __stdcall Create(void* audioGraph, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::LimiterEffectDefinition>(this->shim().Create(*reinterpret_cast<winrt::Windows::Media::Audio::AudioGraph const*>(&audioGraph)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IMediaSourceAudioInputNode> : produce_base<D, winrt::Windows::Media::Audio::IMediaSourceAudioInputNode>
    {
        int32_t __stdcall put_PlaybackSpeedFactor(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PlaybackSpeedFactor(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PlaybackSpeedFactor(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().PlaybackSpeedFactor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Position(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().Position());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Seek(int64_t position) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Seek(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&position));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StartTime(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().StartTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_StartTime(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StartTime(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EndTime(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>>(this->shim().EndTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EndTime(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EndTime(*reinterpret_cast<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LoopCount(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<int32_t>>(this->shim().LoopCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LoopCount(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LoopCount(*reinterpret_cast<winrt::Windows::Foundation::IReference<int32_t> const*>(&value));
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
        int32_t __stdcall get_MediaSource(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Core::MediaSource>(this->shim().MediaSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_MediaSourceCompleted(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().MediaSourceCompleted(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::MediaSourceAudioInputNode, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_MediaSourceCompleted(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MediaSourceCompleted(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IReverbEffectDefinition> : produce_base<D, winrt::Windows::Media::Audio::IReverbEffectDefinition>
    {
        int32_t __stdcall put_WetDryMix(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().WetDryMix(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_WetDryMix(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().WetDryMix());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ReflectionsDelay(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReflectionsDelay(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReflectionsDelay(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().ReflectionsDelay());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ReverbDelay(uint8_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReverbDelay(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReverbDelay(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().ReverbDelay());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RearDelay(uint8_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RearDelay(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RearDelay(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().RearDelay());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PositionLeft(uint8_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PositionLeft(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PositionLeft(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().PositionLeft());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PositionRight(uint8_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PositionRight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PositionRight(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().PositionRight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PositionMatrixLeft(uint8_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PositionMatrixLeft(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PositionMatrixLeft(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().PositionMatrixLeft());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PositionMatrixRight(uint8_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PositionMatrixRight(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PositionMatrixRight(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().PositionMatrixRight());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EarlyDiffusion(uint8_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EarlyDiffusion(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EarlyDiffusion(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().EarlyDiffusion());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LateDiffusion(uint8_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LateDiffusion(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LateDiffusion(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().LateDiffusion());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LowEQGain(uint8_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LowEQGain(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LowEQGain(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().LowEQGain());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LowEQCutoff(uint8_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LowEQCutoff(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LowEQCutoff(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().LowEQCutoff());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HighEQGain(uint8_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HighEQGain(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HighEQGain(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().HighEQGain());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HighEQCutoff(uint8_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HighEQCutoff(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HighEQCutoff(uint8_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint8_t>(this->shim().HighEQCutoff());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RoomFilterFreq(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RoomFilterFreq(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RoomFilterFreq(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().RoomFilterFreq());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RoomFilterMain(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RoomFilterMain(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RoomFilterMain(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().RoomFilterMain());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RoomFilterHF(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RoomFilterHF(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RoomFilterHF(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().RoomFilterHF());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ReflectionsGain(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReflectionsGain(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReflectionsGain(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ReflectionsGain());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ReverbGain(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReverbGain(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReverbGain(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().ReverbGain());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DecayTime(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DecayTime(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DecayTime(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().DecayTime());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Density(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Density(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Density(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().Density());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_RoomSize(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RoomSize(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RoomSize(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().RoomSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DisableLateField(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DisableLateField(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisableLateField(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().DisableLateField());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::IReverbEffectDefinitionFactory> : produce_base<D, winrt::Windows::Media::Audio::IReverbEffectDefinitionFactory>
    {
        int32_t __stdcall Create(void* audioGraph, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::ReverbEffectDefinition>(this->shim().Create(*reinterpret_cast<winrt::Windows::Media::Audio::AudioGraph const*>(&audioGraph)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::ISetDefaultSpatialAudioFormatResult> : produce_base<D, winrt::Windows::Media::Audio::ISetDefaultSpatialAudioFormatResult>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::SetDefaultSpatialAudioFormatStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::ISpatialAudioDeviceConfiguration> : produce_base<D, winrt::Windows::Media::Audio::ISpatialAudioDeviceConfiguration>
    {
        int32_t __stdcall get_DeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsSpatialAudioSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsSpatialAudioSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsSpatialAudioFormatSupported(void* subtype, bool* result) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *result = detach_from<bool>(this->shim().IsSpatialAudioFormatSupported(*reinterpret_cast<hstring const*>(&subtype)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ActiveSpatialAudioFormat(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ActiveSpatialAudioFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DefaultSpatialAudioFormat(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DefaultSpatialAudioFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetDefaultSpatialAudioFormatAsync(void* subtype, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::Audio::SetDefaultSpatialAudioFormatResult>>(this->shim().SetDefaultSpatialAudioFormatAsync(*reinterpret_cast<hstring const*>(&subtype)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_ConfigurationChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().ConfigurationChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Audio::SpatialAudioDeviceConfiguration, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_ConfigurationChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ConfigurationChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::ISpatialAudioDeviceConfigurationStatics> : produce_base<D, winrt::Windows::Media::Audio::ISpatialAudioDeviceConfigurationStatics>
    {
        int32_t __stdcall GetForDeviceId(void* deviceId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Audio::SpatialAudioDeviceConfiguration>(this->shim().GetForDeviceId(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::ISpatialAudioFormatConfiguration> : produce_base<D, winrt::Windows::Media::Audio::ISpatialAudioFormatConfiguration>
    {
        int32_t __stdcall ReportLicenseChangedAsync(void* subtype, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportLicenseChangedAsync(*reinterpret_cast<hstring const*>(&subtype)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportConfigurationChangedAsync(void* subtype, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().ReportConfigurationChangedAsync(*reinterpret_cast<hstring const*>(&subtype)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MixedRealityExclusiveModePolicy(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Audio::MixedRealitySpatialAudioFormatPolicy>(this->shim().MixedRealityExclusiveModePolicy());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_MixedRealityExclusiveModePolicy(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().MixedRealityExclusiveModePolicy(*reinterpret_cast<winrt::Windows::Media::Audio::MixedRealitySpatialAudioFormatPolicy const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::ISpatialAudioFormatConfigurationStatics> : produce_base<D, winrt::Windows::Media::Audio::ISpatialAudioFormatConfigurationStatics>
    {
        int32_t __stdcall GetDefault(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Media::Audio::SpatialAudioFormatConfiguration>(this->shim().GetDefault());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::ISpatialAudioFormatSubtypeStatics> : produce_base<D, winrt::Windows::Media::Audio::ISpatialAudioFormatSubtypeStatics>
    {
        int32_t __stdcall get_WindowsSonic(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().WindowsSonic());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DolbyAtmosForHeadphones(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DolbyAtmosForHeadphones());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DolbyAtmosForHomeTheater(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DolbyAtmosForHomeTheater());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DolbyAtmosForSpeakers(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DolbyAtmosForSpeakers());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DTSHeadphoneX(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DTSHeadphoneX());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DTSXUltra(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DTSXUltra());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Audio::ISpatialAudioFormatSubtypeStatics2> : produce_base<D, winrt::Windows::Media::Audio::ISpatialAudioFormatSubtypeStatics2>
    {
        int32_t __stdcall get_DTSXForHomeTheater(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DTSXForHomeTheater());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Media::Audio
{
    constexpr auto operator|(AudioNodeEmitterSettings const left, AudioNodeEmitterSettings const right) noexcept
    {
        return static_cast<AudioNodeEmitterSettings>(impl::to_underlying_type(left) | impl::to_underlying_type(right));
    }
    constexpr auto operator|=(AudioNodeEmitterSettings& left, AudioNodeEmitterSettings const right) noexcept
    {
        left = left | right;
        return left;
    }
    constexpr auto operator&(AudioNodeEmitterSettings const left, AudioNodeEmitterSettings const right) noexcept
    {
        return static_cast<AudioNodeEmitterSettings>(impl::to_underlying_type(left) & impl::to_underlying_type(right));
    }
    constexpr auto operator&=(AudioNodeEmitterSettings& left, AudioNodeEmitterSettings const right) noexcept
    {
        left = left & right;
        return left;
    }
    constexpr auto operator~(AudioNodeEmitterSettings const value) noexcept
    {
        return static_cast<AudioNodeEmitterSettings>(~impl::to_underlying_type(value));
    }
    constexpr auto operator^(AudioNodeEmitterSettings const left, AudioNodeEmitterSettings const right) noexcept
    {
        return static_cast<AudioNodeEmitterSettings>(impl::to_underlying_type(left) ^ impl::to_underlying_type(right));
    }
    constexpr auto operator^=(AudioNodeEmitterSettings& left, AudioNodeEmitterSettings const right) noexcept
    {
        left = left ^ right;
        return left;
    }
    inline auto AudioGraph::CreateAsync(winrt::Windows::Media::Audio::AudioGraphSettings const& settings)
    {
        return impl::call_factory<AudioGraph, IAudioGraphStatics>([&](IAudioGraphStatics const& f) { return f.CreateAsync(settings); });
    }
    inline AudioGraphSettings::AudioGraphSettings(winrt::Windows::Media::Render::AudioRenderCategory const& audioRenderCategory) :
        AudioGraphSettings(impl::call_factory<AudioGraphSettings, IAudioGraphSettingsFactory>([&](IAudioGraphSettingsFactory const& f) { return f.Create(audioRenderCategory); }))
    {
    }
    inline AudioNodeEmitter::AudioNodeEmitter() :
        AudioNodeEmitter(impl::call_factory_cast<AudioNodeEmitter(*)(winrt::Windows::Foundation::IActivationFactory const&), AudioNodeEmitter>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<AudioNodeEmitter>(); }))
    {
    }
    inline AudioNodeEmitter::AudioNodeEmitter(winrt::Windows::Media::Audio::AudioNodeEmitterShape const& shape, winrt::Windows::Media::Audio::AudioNodeEmitterDecayModel const& decayModel, winrt::Windows::Media::Audio::AudioNodeEmitterSettings const& settings) :
        AudioNodeEmitter(impl::call_factory<AudioNodeEmitter, IAudioNodeEmitterFactory>([&](IAudioNodeEmitterFactory const& f) { return f.CreateAudioNodeEmitter(shape, decayModel, settings); }))
    {
    }
    inline auto AudioNodeEmitterDecayModel::CreateNatural(double minGain, double maxGain, double unityGainDistance, double cutoffDistance)
    {
        return impl::call_factory<AudioNodeEmitterDecayModel, IAudioNodeEmitterDecayModelStatics>([&](IAudioNodeEmitterDecayModelStatics const& f) { return f.CreateNatural(minGain, maxGain, unityGainDistance, cutoffDistance); });
    }
    inline auto AudioNodeEmitterDecayModel::CreateCustom(double minGain, double maxGain)
    {
        return impl::call_factory<AudioNodeEmitterDecayModel, IAudioNodeEmitterDecayModelStatics>([&](IAudioNodeEmitterDecayModelStatics const& f) { return f.CreateCustom(minGain, maxGain); });
    }
    inline auto AudioNodeEmitterShape::CreateCone(double innerAngle, double outerAngle, double outerAngleGain)
    {
        return impl::call_factory<AudioNodeEmitterShape, IAudioNodeEmitterShapeStatics>([&](IAudioNodeEmitterShapeStatics const& f) { return f.CreateCone(innerAngle, outerAngle, outerAngleGain); });
    }
    inline auto AudioNodeEmitterShape::CreateOmnidirectional()
    {
        return impl::call_factory_cast<winrt::Windows::Media::Audio::AudioNodeEmitterShape(*)(IAudioNodeEmitterShapeStatics const&), AudioNodeEmitterShape, IAudioNodeEmitterShapeStatics>([](IAudioNodeEmitterShapeStatics const& f) { return f.CreateOmnidirectional(); });
    }
    inline AudioNodeListener::AudioNodeListener() :
        AudioNodeListener(impl::call_factory_cast<AudioNodeListener(*)(winrt::Windows::Foundation::IActivationFactory const&), AudioNodeListener>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<AudioNodeListener>(); }))
    {
    }
    inline auto AudioPlaybackConnection::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IAudioPlaybackConnectionStatics const&), AudioPlaybackConnection, IAudioPlaybackConnectionStatics>([](IAudioPlaybackConnectionStatics const& f) { return f.GetDeviceSelector(); });
    }
    inline auto AudioPlaybackConnection::TryCreateFromId(param::hstring const& id)
    {
        return impl::call_factory<AudioPlaybackConnection, IAudioPlaybackConnectionStatics>([&](IAudioPlaybackConnectionStatics const& f) { return f.TryCreateFromId(id); });
    }
    inline auto AudioStateMonitor::CreateForRenderMonitoring()
    {
        return impl::call_factory_cast<winrt::Windows::Media::Audio::AudioStateMonitor(*)(IAudioStateMonitorStatics const&), AudioStateMonitor, IAudioStateMonitorStatics>([](IAudioStateMonitorStatics const& f) { return f.CreateForRenderMonitoring(); });
    }
    inline auto AudioStateMonitor::CreateForRenderMonitoring(winrt::Windows::Media::Render::AudioRenderCategory const& category)
    {
        return impl::call_factory<AudioStateMonitor, IAudioStateMonitorStatics>([&](IAudioStateMonitorStatics const& f) { return f.CreateForRenderMonitoring(category); });
    }
    inline auto AudioStateMonitor::CreateForRenderMonitoring(winrt::Windows::Media::Render::AudioRenderCategory const& category, winrt::Windows::Media::Devices::AudioDeviceRole const& role)
    {
        return impl::call_factory<AudioStateMonitor, IAudioStateMonitorStatics>([&](IAudioStateMonitorStatics const& f) { return f.CreateForRenderMonitoring(category, role); });
    }
    inline auto AudioStateMonitor::CreateForRenderMonitoringWithCategoryAndDeviceId(winrt::Windows::Media::Render::AudioRenderCategory const& category, param::hstring const& deviceId)
    {
        return impl::call_factory<AudioStateMonitor, IAudioStateMonitorStatics>([&](IAudioStateMonitorStatics const& f) { return f.CreateForRenderMonitoringWithCategoryAndDeviceId(category, deviceId); });
    }
    inline auto AudioStateMonitor::CreateForCaptureMonitoring()
    {
        return impl::call_factory_cast<winrt::Windows::Media::Audio::AudioStateMonitor(*)(IAudioStateMonitorStatics const&), AudioStateMonitor, IAudioStateMonitorStatics>([](IAudioStateMonitorStatics const& f) { return f.CreateForCaptureMonitoring(); });
    }
    inline auto AudioStateMonitor::CreateForCaptureMonitoring(winrt::Windows::Media::Capture::MediaCategory const& category)
    {
        return impl::call_factory<AudioStateMonitor, IAudioStateMonitorStatics>([&](IAudioStateMonitorStatics const& f) { return f.CreateForCaptureMonitoring(category); });
    }
    inline auto AudioStateMonitor::CreateForCaptureMonitoring(winrt::Windows::Media::Capture::MediaCategory const& category, winrt::Windows::Media::Devices::AudioDeviceRole const& role)
    {
        return impl::call_factory<AudioStateMonitor, IAudioStateMonitorStatics>([&](IAudioStateMonitorStatics const& f) { return f.CreateForCaptureMonitoring(category, role); });
    }
    inline auto AudioStateMonitor::CreateForCaptureMonitoringWithCategoryAndDeviceId(winrt::Windows::Media::Capture::MediaCategory const& category, param::hstring const& deviceId)
    {
        return impl::call_factory<AudioStateMonitor, IAudioStateMonitorStatics>([&](IAudioStateMonitorStatics const& f) { return f.CreateForCaptureMonitoringWithCategoryAndDeviceId(category, deviceId); });
    }
    inline EchoEffectDefinition::EchoEffectDefinition(winrt::Windows::Media::Audio::AudioGraph const& audioGraph) :
        EchoEffectDefinition(impl::call_factory<EchoEffectDefinition, IEchoEffectDefinitionFactory>([&](IEchoEffectDefinitionFactory const& f) { return f.Create(audioGraph); }))
    {
    }
    inline EqualizerEffectDefinition::EqualizerEffectDefinition(winrt::Windows::Media::Audio::AudioGraph const& audioGraph) :
        EqualizerEffectDefinition(impl::call_factory<EqualizerEffectDefinition, IEqualizerEffectDefinitionFactory>([&](IEqualizerEffectDefinitionFactory const& f) { return f.Create(audioGraph); }))
    {
    }
    inline LimiterEffectDefinition::LimiterEffectDefinition(winrt::Windows::Media::Audio::AudioGraph const& audioGraph) :
        LimiterEffectDefinition(impl::call_factory<LimiterEffectDefinition, ILimiterEffectDefinitionFactory>([&](ILimiterEffectDefinitionFactory const& f) { return f.Create(audioGraph); }))
    {
    }
    inline ReverbEffectDefinition::ReverbEffectDefinition(winrt::Windows::Media::Audio::AudioGraph const& audioGraph) :
        ReverbEffectDefinition(impl::call_factory<ReverbEffectDefinition, IReverbEffectDefinitionFactory>([&](IReverbEffectDefinitionFactory const& f) { return f.Create(audioGraph); }))
    {
    }
    inline auto SpatialAudioDeviceConfiguration::GetForDeviceId(param::hstring const& deviceId)
    {
        return impl::call_factory<SpatialAudioDeviceConfiguration, ISpatialAudioDeviceConfigurationStatics>([&](ISpatialAudioDeviceConfigurationStatics const& f) { return f.GetForDeviceId(deviceId); });
    }
    inline auto SpatialAudioFormatConfiguration::GetDefault()
    {
        return impl::call_factory_cast<winrt::Windows::Media::Audio::SpatialAudioFormatConfiguration(*)(ISpatialAudioFormatConfigurationStatics const&), SpatialAudioFormatConfiguration, ISpatialAudioFormatConfigurationStatics>([](ISpatialAudioFormatConfigurationStatics const& f) { return f.GetDefault(); });
    }
    inline auto SpatialAudioFormatSubtype::WindowsSonic()
    {
        return impl::call_factory_cast<hstring(*)(ISpatialAudioFormatSubtypeStatics const&), SpatialAudioFormatSubtype, ISpatialAudioFormatSubtypeStatics>([](ISpatialAudioFormatSubtypeStatics const& f) { return f.WindowsSonic(); });
    }
    inline auto SpatialAudioFormatSubtype::DolbyAtmosForHeadphones()
    {
        return impl::call_factory_cast<hstring(*)(ISpatialAudioFormatSubtypeStatics const&), SpatialAudioFormatSubtype, ISpatialAudioFormatSubtypeStatics>([](ISpatialAudioFormatSubtypeStatics const& f) { return f.DolbyAtmosForHeadphones(); });
    }
    inline auto SpatialAudioFormatSubtype::DolbyAtmosForHomeTheater()
    {
        return impl::call_factory_cast<hstring(*)(ISpatialAudioFormatSubtypeStatics const&), SpatialAudioFormatSubtype, ISpatialAudioFormatSubtypeStatics>([](ISpatialAudioFormatSubtypeStatics const& f) { return f.DolbyAtmosForHomeTheater(); });
    }
    inline auto SpatialAudioFormatSubtype::DolbyAtmosForSpeakers()
    {
        return impl::call_factory_cast<hstring(*)(ISpatialAudioFormatSubtypeStatics const&), SpatialAudioFormatSubtype, ISpatialAudioFormatSubtypeStatics>([](ISpatialAudioFormatSubtypeStatics const& f) { return f.DolbyAtmosForSpeakers(); });
    }
    inline auto SpatialAudioFormatSubtype::DTSHeadphoneX()
    {
        return impl::call_factory_cast<hstring(*)(ISpatialAudioFormatSubtypeStatics const&), SpatialAudioFormatSubtype, ISpatialAudioFormatSubtypeStatics>([](ISpatialAudioFormatSubtypeStatics const& f) { return f.DTSHeadphoneX(); });
    }
    inline auto SpatialAudioFormatSubtype::DTSXUltra()
    {
        return impl::call_factory_cast<hstring(*)(ISpatialAudioFormatSubtypeStatics const&), SpatialAudioFormatSubtype, ISpatialAudioFormatSubtypeStatics>([](ISpatialAudioFormatSubtypeStatics const& f) { return f.DTSXUltra(); });
    }
    inline auto SpatialAudioFormatSubtype::DTSXForHomeTheater()
    {
        return impl::call_factory_cast<hstring(*)(ISpatialAudioFormatSubtypeStatics2 const&), SpatialAudioFormatSubtype, ISpatialAudioFormatSubtypeStatics2>([](ISpatialAudioFormatSubtypeStatics2 const& f) { return f.DTSXForHomeTheater(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Media::Audio::IAudioDeviceInputNode> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioDeviceOutputNode> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioFileInputNode> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioFileOutputNode> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioFrameCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioFrameInputNode> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioFrameOutputNode> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioGraph> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioGraph2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioGraph3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioGraphConnection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioGraphSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioGraphSettings2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioGraphSettingsFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioGraphStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioGraphUnrecoverableErrorOccurredEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioInputNode> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioInputNode2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioNode> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioNodeEmitter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioNodeEmitter2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioNodeEmitterConeProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioNodeEmitterDecayModel> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioNodeEmitterDecayModelStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioNodeEmitterFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioNodeEmitterNaturalDecayModelProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioNodeEmitterShape> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioNodeEmitterShapeStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioNodeListener> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioNodeWithListener> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioPlaybackConnection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioPlaybackConnectionOpenResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioPlaybackConnectionStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioStateMonitor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IAudioStateMonitorStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::ICreateAudioDeviceInputNodeResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::ICreateAudioDeviceInputNodeResult2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::ICreateAudioDeviceOutputNodeResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::ICreateAudioDeviceOutputNodeResult2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::ICreateAudioFileInputNodeResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::ICreateAudioFileInputNodeResult2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::ICreateAudioFileOutputNodeResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::ICreateAudioFileOutputNodeResult2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::ICreateAudioGraphResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::ICreateAudioGraphResult2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::ICreateMediaSourceAudioInputNodeResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::ICreateMediaSourceAudioInputNodeResult2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IEchoEffectDefinition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IEchoEffectDefinitionFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IEqualizerBand> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IEqualizerEffectDefinition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IEqualizerEffectDefinitionFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IFrameInputNodeQuantumStartedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::ILimiterEffectDefinition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::ILimiterEffectDefinitionFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IMediaSourceAudioInputNode> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IReverbEffectDefinition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::IReverbEffectDefinitionFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::ISetDefaultSpatialAudioFormatResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::ISpatialAudioDeviceConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::ISpatialAudioDeviceConfigurationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::ISpatialAudioFormatConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::ISpatialAudioFormatConfigurationStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::ISpatialAudioFormatSubtypeStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::ISpatialAudioFormatSubtypeStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::AudioDeviceInputNode> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::AudioDeviceOutputNode> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::AudioFileInputNode> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::AudioFileOutputNode> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::AudioFrameCompletedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::AudioFrameInputNode> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::AudioFrameOutputNode> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::AudioGraph> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::AudioGraphBatchUpdater> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::AudioGraphConnection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::AudioGraphSettings> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::AudioGraphUnrecoverableErrorOccurredEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::AudioNodeEmitter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::AudioNodeEmitterConeProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::AudioNodeEmitterDecayModel> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::AudioNodeEmitterNaturalDecayModelProperties> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::AudioNodeEmitterShape> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::AudioNodeListener> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::AudioPlaybackConnection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::AudioPlaybackConnectionOpenResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::AudioStateMonitor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::AudioSubmixNode> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::CreateAudioDeviceInputNodeResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::CreateAudioDeviceOutputNodeResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::CreateAudioFileInputNodeResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::CreateAudioFileOutputNodeResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::CreateAudioGraphResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::CreateMediaSourceAudioInputNodeResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::EchoEffectDefinition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::EqualizerBand> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::EqualizerEffectDefinition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::FrameInputNodeQuantumStartedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::LimiterEffectDefinition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::MediaSourceAudioInputNode> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::ReverbEffectDefinition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::SetDefaultSpatialAudioFormatResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::SpatialAudioDeviceConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::SpatialAudioFormatConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Audio::SpatialAudioFormatSubtype> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
