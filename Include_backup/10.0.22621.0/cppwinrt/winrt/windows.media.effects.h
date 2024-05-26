// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_Effects_H
#define WINRT_Windows_Media_Effects_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Media.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Foundation.Numerics.2.h"
#include "winrt/impl/Windows.Graphics.DirectX.Direct3D11.2.h"
#include "winrt/impl/Windows.Media.2.h"
#include "winrt/impl/Windows.Media.Capture.2.h"
#include "winrt/impl/Windows.Media.Editing.2.h"
#include "winrt/impl/Windows.Media.MediaProperties.2.h"
#include "winrt/impl/Windows.Media.Playback.2.h"
#include "winrt/impl/Windows.Media.Render.2.h"
#include "winrt/impl/Windows.Media.Transcoding.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.2.h"
#include "winrt/impl/Windows.Media.Effects.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Effects_IAudioCaptureEffectsManager<D>::AudioCaptureEffectsChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Effects::AudioCaptureEffectsManager, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IAudioCaptureEffectsManager)->add_AudioCaptureEffectsChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Effects_IAudioCaptureEffectsManager<D>::AudioCaptureEffectsChanged_revoker consume_Windows_Media_Effects_IAudioCaptureEffectsManager<D>::AudioCaptureEffectsChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Effects::AudioCaptureEffectsManager, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, AudioCaptureEffectsChanged_revoker>(this, AudioCaptureEffectsChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Effects_IAudioCaptureEffectsManager<D>::AudioCaptureEffectsChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IAudioCaptureEffectsManager)->remove_AudioCaptureEffectsChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Effects::AudioEffect>) consume_Windows_Media_Effects_IAudioCaptureEffectsManager<D>::GetAudioCaptureEffects() const
    {
        void* effects{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IAudioCaptureEffectsManager)->GetAudioCaptureEffects(&effects));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Effects::AudioEffect>{ effects, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Effects::AudioEffectType) consume_Windows_Media_Effects_IAudioEffect<D>::AudioEffectType() const
    {
        winrt::Windows::Media::Effects::AudioEffectType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IAudioEffect)->get_AudioEffectType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Effects_IAudioEffectDefinition<D>::ActivatableClassId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IAudioEffectDefinition)->get_ActivatableClassId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IPropertySet) consume_Windows_Media_Effects_IAudioEffectDefinition<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IAudioEffectDefinition)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IPropertySet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Effects::AudioEffectDefinition) consume_Windows_Media_Effects_IAudioEffectDefinitionFactory<D>::Create(param::hstring const& activatableClassId) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IAudioEffectDefinitionFactory)->Create(*(void**)(&activatableClassId), &value));
        return winrt::Windows::Media::Effects::AudioEffectDefinition{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Effects::AudioEffectDefinition) consume_Windows_Media_Effects_IAudioEffectDefinitionFactory<D>::CreateWithProperties(param::hstring const& activatableClassId, winrt::Windows::Foundation::Collections::IPropertySet const& props) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IAudioEffectDefinitionFactory)->CreateWithProperties(*(void**)(&activatableClassId), *(void**)(&props), &value));
        return winrt::Windows::Media::Effects::AudioEffectDefinition{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Effects::AudioRenderEffectsManager) consume_Windows_Media_Effects_IAudioEffectsManagerStatics<D>::CreateAudioRenderEffectsManager(param::hstring const& deviceId, winrt::Windows::Media::Render::AudioRenderCategory const& category) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IAudioEffectsManagerStatics)->CreateAudioRenderEffectsManager(*(void**)(&deviceId), static_cast<int32_t>(category), &value));
        return winrt::Windows::Media::Effects::AudioRenderEffectsManager{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Effects::AudioRenderEffectsManager) consume_Windows_Media_Effects_IAudioEffectsManagerStatics<D>::CreateAudioRenderEffectsManager(param::hstring const& deviceId, winrt::Windows::Media::Render::AudioRenderCategory const& category, winrt::Windows::Media::AudioProcessing const& mode) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IAudioEffectsManagerStatics)->CreateAudioRenderEffectsManagerWithMode(*(void**)(&deviceId), static_cast<int32_t>(category), static_cast<int32_t>(mode), &value));
        return winrt::Windows::Media::Effects::AudioRenderEffectsManager{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Effects::AudioCaptureEffectsManager) consume_Windows_Media_Effects_IAudioEffectsManagerStatics<D>::CreateAudioCaptureEffectsManager(param::hstring const& deviceId, winrt::Windows::Media::Capture::MediaCategory const& category) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IAudioEffectsManagerStatics)->CreateAudioCaptureEffectsManager(*(void**)(&deviceId), static_cast<int32_t>(category), &value));
        return winrt::Windows::Media::Effects::AudioCaptureEffectsManager{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Effects::AudioCaptureEffectsManager) consume_Windows_Media_Effects_IAudioEffectsManagerStatics<D>::CreateAudioCaptureEffectsManager(param::hstring const& deviceId, winrt::Windows::Media::Capture::MediaCategory const& category, winrt::Windows::Media::AudioProcessing const& mode) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IAudioEffectsManagerStatics)->CreateAudioCaptureEffectsManagerWithMode(*(void**)(&deviceId), static_cast<int32_t>(category), static_cast<int32_t>(mode), &value));
        return winrt::Windows::Media::Effects::AudioCaptureEffectsManager{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Effects_IAudioRenderEffectsManager<D>::AudioRenderEffectsChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Effects::AudioRenderEffectsManager, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IAudioRenderEffectsManager)->add_AudioRenderEffectsChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Effects_IAudioRenderEffectsManager<D>::AudioRenderEffectsChanged_revoker consume_Windows_Media_Effects_IAudioRenderEffectsManager<D>::AudioRenderEffectsChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Effects::AudioRenderEffectsManager, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, AudioRenderEffectsChanged_revoker>(this, AudioRenderEffectsChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Effects_IAudioRenderEffectsManager<D>::AudioRenderEffectsChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IAudioRenderEffectsManager)->remove_AudioRenderEffectsChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Effects::AudioEffect>) consume_Windows_Media_Effects_IAudioRenderEffectsManager<D>::GetAudioRenderEffects() const
    {
        void* effects{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IAudioRenderEffectsManager)->GetAudioRenderEffects(&effects));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Effects::AudioEffect>{ effects, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType) consume_Windows_Media_Effects_IAudioRenderEffectsManager2<D>::EffectsProviderThumbnail() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IAudioRenderEffectsManager2)->get_EffectsProviderThumbnail(&value));
        return winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Effects_IAudioRenderEffectsManager2<D>::EffectsProviderSettingsLabel() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IAudioRenderEffectsManager2)->get_EffectsProviderSettingsLabel(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Effects_IAudioRenderEffectsManager2<D>::ShowSettingsUI() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IAudioRenderEffectsManager2)->ShowSettingsUI());
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Effects_IBasicAudioEffect<D>::UseInputFrameForOutput() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IBasicAudioEffect)->get_UseInputFrameForOutput(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::MediaProperties::AudioEncodingProperties>) consume_Windows_Media_Effects_IBasicAudioEffect<D>::SupportedEncodingProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IBasicAudioEffect)->get_SupportedEncodingProperties(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::MediaProperties::AudioEncodingProperties>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Effects_IBasicAudioEffect<D>::SetEncodingProperties(winrt::Windows::Media::MediaProperties::AudioEncodingProperties const& encodingProperties) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IBasicAudioEffect)->SetEncodingProperties(*(void**)(&encodingProperties)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Effects_IBasicAudioEffect<D>::ProcessFrame(winrt::Windows::Media::Effects::ProcessAudioFrameContext const& context) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IBasicAudioEffect)->ProcessFrame(*(void**)(&context)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Effects_IBasicAudioEffect<D>::Close(winrt::Windows::Media::Effects::MediaEffectClosedReason const& reason) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IBasicAudioEffect)->Close(static_cast<int32_t>(reason)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Effects_IBasicAudioEffect<D>::DiscardQueuedFrames() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IBasicAudioEffect)->DiscardQueuedFrames());
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Effects_IBasicVideoEffect<D>::IsReadOnly() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IBasicVideoEffect)->get_IsReadOnly(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Effects::MediaMemoryTypes) consume_Windows_Media_Effects_IBasicVideoEffect<D>::SupportedMemoryTypes() const
    {
        winrt::Windows::Media::Effects::MediaMemoryTypes value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IBasicVideoEffect)->get_SupportedMemoryTypes(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Effects_IBasicVideoEffect<D>::TimeIndependent() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IBasicVideoEffect)->get_TimeIndependent(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::MediaProperties::VideoEncodingProperties>) consume_Windows_Media_Effects_IBasicVideoEffect<D>::SupportedEncodingProperties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IBasicVideoEffect)->get_SupportedEncodingProperties(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::MediaProperties::VideoEncodingProperties>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Effects_IBasicVideoEffect<D>::SetEncodingProperties(winrt::Windows::Media::MediaProperties::VideoEncodingProperties const& encodingProperties, winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IBasicVideoEffect)->SetEncodingProperties(*(void**)(&encodingProperties), *(void**)(&device)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Effects_IBasicVideoEffect<D>::ProcessFrame(winrt::Windows::Media::Effects::ProcessVideoFrameContext const& context) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IBasicVideoEffect)->ProcessFrame(*(void**)(&context)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Effects_IBasicVideoEffect<D>::Close(winrt::Windows::Media::Effects::MediaEffectClosedReason const& reason) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IBasicVideoEffect)->Close(static_cast<int32_t>(reason)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Effects_IBasicVideoEffect<D>::DiscardQueuedFrames() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IBasicVideoEffect)->DiscardQueuedFrames());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface>) consume_Windows_Media_Effects_ICompositeVideoFrameContext<D>::SurfacesToOverlay() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::ICompositeVideoFrameContext)->get_SurfacesToOverlay(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::VideoFrame) consume_Windows_Media_Effects_ICompositeVideoFrameContext<D>::BackgroundFrame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::ICompositeVideoFrameContext)->get_BackgroundFrame(&value));
        return winrt::Windows::Media::VideoFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::VideoFrame) consume_Windows_Media_Effects_ICompositeVideoFrameContext<D>::OutputFrame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::ICompositeVideoFrameContext)->get_OutputFrame(&value));
        return winrt::Windows::Media::VideoFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Editing::MediaOverlay) consume_Windows_Media_Effects_ICompositeVideoFrameContext<D>::GetOverlayForSurface(winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const& surfaceToOverlay) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::ICompositeVideoFrameContext)->GetOverlayForSurface(*(void**)(&surfaceToOverlay), &value));
        return winrt::Windows::Media::Editing::MediaOverlay{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::AudioFrame) consume_Windows_Media_Effects_IProcessAudioFrameContext<D>::InputFrame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IProcessAudioFrameContext)->get_InputFrame(&value));
        return winrt::Windows::Media::AudioFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::AudioFrame) consume_Windows_Media_Effects_IProcessAudioFrameContext<D>::OutputFrame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IProcessAudioFrameContext)->get_OutputFrame(&value));
        return winrt::Windows::Media::AudioFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::VideoFrame) consume_Windows_Media_Effects_IProcessVideoFrameContext<D>::InputFrame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IProcessVideoFrameContext)->get_InputFrame(&value));
        return winrt::Windows::Media::VideoFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::VideoFrame) consume_Windows_Media_Effects_IProcessVideoFrameContext<D>::OutputFrame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IProcessVideoFrameContext)->get_OutputFrame(&value));
        return winrt::Windows::Media::VideoFrame{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Effects_IVideoCompositor<D>::TimeIndependent() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoCompositor)->get_TimeIndependent(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Effects_IVideoCompositor<D>::SetEncodingProperties(winrt::Windows::Media::MediaProperties::VideoEncodingProperties const& backgroundProperties, winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const& device) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoCompositor)->SetEncodingProperties(*(void**)(&backgroundProperties), *(void**)(&device)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Effects_IVideoCompositor<D>::CompositeFrame(winrt::Windows::Media::Effects::CompositeVideoFrameContext const& context) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoCompositor)->CompositeFrame(*(void**)(&context)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Effects_IVideoCompositor<D>::Close(winrt::Windows::Media::Effects::MediaEffectClosedReason const& reason) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoCompositor)->Close(static_cast<int32_t>(reason)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Effects_IVideoCompositor<D>::DiscardQueuedFrames() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoCompositor)->DiscardQueuedFrames());
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Effects_IVideoCompositorDefinition<D>::ActivatableClassId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoCompositorDefinition)->get_ActivatableClassId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IPropertySet) consume_Windows_Media_Effects_IVideoCompositorDefinition<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoCompositorDefinition)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IPropertySet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Effects::VideoCompositorDefinition) consume_Windows_Media_Effects_IVideoCompositorDefinitionFactory<D>::Create(param::hstring const& activatableClassId) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoCompositorDefinitionFactory)->Create(*(void**)(&activatableClassId), &value));
        return winrt::Windows::Media::Effects::VideoCompositorDefinition{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Effects::VideoCompositorDefinition) consume_Windows_Media_Effects_IVideoCompositorDefinitionFactory<D>::CreateWithProperties(param::hstring const& activatableClassId, winrt::Windows::Foundation::Collections::IPropertySet const& props) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoCompositorDefinitionFactory)->CreateWithProperties(*(void**)(&activatableClassId), *(void**)(&props), &value));
        return winrt::Windows::Media::Effects::VideoCompositorDefinition{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_Effects_IVideoEffectDefinition<D>::ActivatableClassId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoEffectDefinition)->get_ActivatableClassId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IPropertySet) consume_Windows_Media_Effects_IVideoEffectDefinition<D>::Properties() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoEffectDefinition)->get_Properties(&value));
        return winrt::Windows::Foundation::Collections::IPropertySet{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Effects::VideoEffectDefinition) consume_Windows_Media_Effects_IVideoEffectDefinitionFactory<D>::Create(param::hstring const& activatableClassId) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoEffectDefinitionFactory)->Create(*(void**)(&activatableClassId), &value));
        return winrt::Windows::Media::Effects::VideoEffectDefinition{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Effects::VideoEffectDefinition) consume_Windows_Media_Effects_IVideoEffectDefinitionFactory<D>::CreateWithProperties(param::hstring const& activatableClassId, winrt::Windows::Foundation::Collections::IPropertySet const& props) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoEffectDefinitionFactory)->CreateWithProperties(*(void**)(&activatableClassId), *(void**)(&props), &value));
        return winrt::Windows::Media::Effects::VideoEffectDefinition{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Color) consume_Windows_Media_Effects_IVideoTransformEffectDefinition<D>::PaddingColor() const
    {
        winrt::Windows::UI::Color value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoTransformEffectDefinition)->get_PaddingColor(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Effects_IVideoTransformEffectDefinition<D>::PaddingColor(winrt::Windows::UI::Color const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoTransformEffectDefinition)->put_PaddingColor(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) consume_Windows_Media_Effects_IVideoTransformEffectDefinition<D>::OutputSize() const
    {
        winrt::Windows::Foundation::Size value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoTransformEffectDefinition)->get_OutputSize(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Effects_IVideoTransformEffectDefinition<D>::OutputSize(winrt::Windows::Foundation::Size const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoTransformEffectDefinition)->put_OutputSize(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) consume_Windows_Media_Effects_IVideoTransformEffectDefinition<D>::CropRectangle() const
    {
        winrt::Windows::Foundation::Rect value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoTransformEffectDefinition)->get_CropRectangle(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Effects_IVideoTransformEffectDefinition<D>::CropRectangle(winrt::Windows::Foundation::Rect const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoTransformEffectDefinition)->put_CropRectangle(impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::MediaRotation) consume_Windows_Media_Effects_IVideoTransformEffectDefinition<D>::Rotation() const
    {
        winrt::Windows::Media::MediaProperties::MediaRotation value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoTransformEffectDefinition)->get_Rotation(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Effects_IVideoTransformEffectDefinition<D>::Rotation(winrt::Windows::Media::MediaProperties::MediaRotation const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoTransformEffectDefinition)->put_Rotation(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::MediaMirroringOptions) consume_Windows_Media_Effects_IVideoTransformEffectDefinition<D>::Mirror() const
    {
        winrt::Windows::Media::MediaProperties::MediaMirroringOptions value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoTransformEffectDefinition)->get_Mirror(reinterpret_cast<uint32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Effects_IVideoTransformEffectDefinition<D>::Mirror(winrt::Windows::Media::MediaProperties::MediaMirroringOptions const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoTransformEffectDefinition)->put_Mirror(static_cast<uint32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Effects_IVideoTransformEffectDefinition<D>::ProcessingAlgorithm(winrt::Windows::Media::Transcoding::MediaVideoProcessingAlgorithm const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoTransformEffectDefinition)->put_ProcessingAlgorithm(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Transcoding::MediaVideoProcessingAlgorithm) consume_Windows_Media_Effects_IVideoTransformEffectDefinition<D>::ProcessingAlgorithm() const
    {
        winrt::Windows::Media::Transcoding::MediaVideoProcessingAlgorithm value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoTransformEffectDefinition)->get_ProcessingAlgorithm(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Effects::VideoTransformSphericalProjection) consume_Windows_Media_Effects_IVideoTransformEffectDefinition2<D>::SphericalProjection() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoTransformEffectDefinition2)->get_SphericalProjection(&value));
        return winrt::Windows::Media::Effects::VideoTransformSphericalProjection{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_Effects_IVideoTransformSphericalProjection<D>::IsEnabled() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoTransformSphericalProjection)->get_IsEnabled(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Effects_IVideoTransformSphericalProjection<D>::IsEnabled(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoTransformSphericalProjection)->put_IsEnabled(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::MediaProperties::SphericalVideoFrameFormat) consume_Windows_Media_Effects_IVideoTransformSphericalProjection<D>::FrameFormat() const
    {
        winrt::Windows::Media::MediaProperties::SphericalVideoFrameFormat value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoTransformSphericalProjection)->get_FrameFormat(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Effects_IVideoTransformSphericalProjection<D>::FrameFormat(winrt::Windows::Media::MediaProperties::SphericalVideoFrameFormat const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoTransformSphericalProjection)->put_FrameFormat(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::Playback::SphericalVideoProjectionMode) consume_Windows_Media_Effects_IVideoTransformSphericalProjection<D>::ProjectionMode() const
    {
        winrt::Windows::Media::Playback::SphericalVideoProjectionMode value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoTransformSphericalProjection)->get_ProjectionMode(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Effects_IVideoTransformSphericalProjection<D>::ProjectionMode(winrt::Windows::Media::Playback::SphericalVideoProjectionMode const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoTransformSphericalProjection)->put_ProjectionMode(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_Effects_IVideoTransformSphericalProjection<D>::HorizontalFieldOfViewInDegrees() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoTransformSphericalProjection)->get_HorizontalFieldOfViewInDegrees(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Effects_IVideoTransformSphericalProjection<D>::HorizontalFieldOfViewInDegrees(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoTransformSphericalProjection)->put_HorizontalFieldOfViewInDegrees(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Numerics::quaternion) consume_Windows_Media_Effects_IVideoTransformSphericalProjection<D>::ViewOrientation() const
    {
        winrt::Windows::Foundation::Numerics::quaternion value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoTransformSphericalProjection)->get_ViewOrientation(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Effects_IVideoTransformSphericalProjection<D>::ViewOrientation(winrt::Windows::Foundation::Numerics::quaternion const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Effects::IVideoTransformSphericalProjection)->put_ViewOrientation(impl::bind_in(value)));
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Effects::IAudioCaptureEffectsManager> : produce_base<D, winrt::Windows::Media::Effects::IAudioCaptureEffectsManager>
    {
        int32_t __stdcall add_AudioCaptureEffectsChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AudioCaptureEffectsChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Effects::AudioCaptureEffectsManager, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AudioCaptureEffectsChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AudioCaptureEffectsChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall GetAudioCaptureEffects(void** effects) noexcept final try
        {
            clear_abi(effects);
            typename D::abi_guard guard(this->shim());
            *effects = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Effects::AudioEffect>>(this->shim().GetAudioCaptureEffects());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Effects::IAudioEffect> : produce_base<D, winrt::Windows::Media::Effects::IAudioEffect>
    {
        int32_t __stdcall get_AudioEffectType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Effects::AudioEffectType>(this->shim().AudioEffectType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::Effects::IAudioEffectDefinition> : produce_base<D, winrt::Windows::Media::Effects::IAudioEffectDefinition>
    {
        int32_t __stdcall get_ActivatableClassId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ActivatableClassId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IPropertySet>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Effects::IAudioEffectDefinitionFactory> : produce_base<D, winrt::Windows::Media::Effects::IAudioEffectDefinitionFactory>
    {
        int32_t __stdcall Create(void* activatableClassId, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Effects::AudioEffectDefinition>(this->shim().Create(*reinterpret_cast<hstring const*>(&activatableClassId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithProperties(void* activatableClassId, void* props, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Effects::AudioEffectDefinition>(this->shim().CreateWithProperties(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<winrt::Windows::Foundation::Collections::IPropertySet const*>(&props)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Effects::IAudioEffectsManagerStatics> : produce_base<D, winrt::Windows::Media::Effects::IAudioEffectsManagerStatics>
    {
        int32_t __stdcall CreateAudioRenderEffectsManager(void* deviceId, int32_t category, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Effects::AudioRenderEffectsManager>(this->shim().CreateAudioRenderEffectsManager(*reinterpret_cast<hstring const*>(&deviceId), *reinterpret_cast<winrt::Windows::Media::Render::AudioRenderCategory const*>(&category)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateAudioRenderEffectsManagerWithMode(void* deviceId, int32_t category, int32_t mode, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Effects::AudioRenderEffectsManager>(this->shim().CreateAudioRenderEffectsManager(*reinterpret_cast<hstring const*>(&deviceId), *reinterpret_cast<winrt::Windows::Media::Render::AudioRenderCategory const*>(&category), *reinterpret_cast<winrt::Windows::Media::AudioProcessing const*>(&mode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateAudioCaptureEffectsManager(void* deviceId, int32_t category, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Effects::AudioCaptureEffectsManager>(this->shim().CreateAudioCaptureEffectsManager(*reinterpret_cast<hstring const*>(&deviceId), *reinterpret_cast<winrt::Windows::Media::Capture::MediaCategory const*>(&category)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateAudioCaptureEffectsManagerWithMode(void* deviceId, int32_t category, int32_t mode, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Effects::AudioCaptureEffectsManager>(this->shim().CreateAudioCaptureEffectsManager(*reinterpret_cast<hstring const*>(&deviceId), *reinterpret_cast<winrt::Windows::Media::Capture::MediaCategory const*>(&category), *reinterpret_cast<winrt::Windows::Media::AudioProcessing const*>(&mode)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Effects::IAudioRenderEffectsManager> : produce_base<D, winrt::Windows::Media::Effects::IAudioRenderEffectsManager>
    {
        int32_t __stdcall add_AudioRenderEffectsChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().AudioRenderEffectsChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Media::Effects::AudioRenderEffectsManager, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_AudioRenderEffectsChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AudioRenderEffectsChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall GetAudioRenderEffects(void** effects) noexcept final try
        {
            clear_abi(effects);
            typename D::abi_guard guard(this->shim());
            *effects = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::Effects::AudioEffect>>(this->shim().GetAudioRenderEffects());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Effects::IAudioRenderEffectsManager2> : produce_base<D, winrt::Windows::Media::Effects::IAudioRenderEffectsManager2>
    {
        int32_t __stdcall get_EffectsProviderThumbnail(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType>(this->shim().EffectsProviderThumbnail());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EffectsProviderSettingsLabel(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().EffectsProviderSettingsLabel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShowSettingsUI() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowSettingsUI();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::Effects::IBasicAudioEffect> : produce_base<D, winrt::Windows::Media::Effects::IBasicAudioEffect>
    {
        int32_t __stdcall get_UseInputFrameForOutput(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().UseInputFrameForOutput());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedEncodingProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::MediaProperties::AudioEncodingProperties>>(this->shim().SupportedEncodingProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetEncodingProperties(void* encodingProperties) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetEncodingProperties(*reinterpret_cast<winrt::Windows::Media::MediaProperties::AudioEncodingProperties const*>(&encodingProperties));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ProcessFrame(void* context) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProcessFrame(*reinterpret_cast<winrt::Windows::Media::Effects::ProcessAudioFrameContext const*>(&context));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Close(int32_t reason) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Close(*reinterpret_cast<winrt::Windows::Media::Effects::MediaEffectClosedReason const*>(&reason));
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
    };
    template <typename D>
    struct produce<D, winrt::Windows::Media::Effects::IBasicVideoEffect> : produce_base<D, winrt::Windows::Media::Effects::IBasicVideoEffect>
    {
        int32_t __stdcall get_IsReadOnly(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsReadOnly());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedMemoryTypes(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Effects::MediaMemoryTypes>(this->shim().SupportedMemoryTypes());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TimeIndependent(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().TimeIndependent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedEncodingProperties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::MediaProperties::VideoEncodingProperties>>(this->shim().SupportedEncodingProperties());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetEncodingProperties(void* encodingProperties, void* device) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetEncodingProperties(*reinterpret_cast<winrt::Windows::Media::MediaProperties::VideoEncodingProperties const*>(&encodingProperties), *reinterpret_cast<winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const*>(&device));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ProcessFrame(void* context) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProcessFrame(*reinterpret_cast<winrt::Windows::Media::Effects::ProcessVideoFrameContext const*>(&context));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Close(int32_t reason) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Close(*reinterpret_cast<winrt::Windows::Media::Effects::MediaEffectClosedReason const*>(&reason));
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
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Effects::ICompositeVideoFrameContext> : produce_base<D, winrt::Windows::Media::Effects::ICompositeVideoFrameContext>
    {
        int32_t __stdcall get_SurfacesToOverlay(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface>>(this->shim().SurfacesToOverlay());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BackgroundFrame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::VideoFrame>(this->shim().BackgroundFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OutputFrame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::VideoFrame>(this->shim().OutputFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetOverlayForSurface(void* surfaceToOverlay, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Editing::MediaOverlay>(this->shim().GetOverlayForSurface(*reinterpret_cast<winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DSurface const*>(&surfaceToOverlay)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Effects::IProcessAudioFrameContext> : produce_base<D, winrt::Windows::Media::Effects::IProcessAudioFrameContext>
    {
        int32_t __stdcall get_InputFrame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::AudioFrame>(this->shim().InputFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OutputFrame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::AudioFrame>(this->shim().OutputFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Effects::IProcessVideoFrameContext> : produce_base<D, winrt::Windows::Media::Effects::IProcessVideoFrameContext>
    {
        int32_t __stdcall get_InputFrame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::VideoFrame>(this->shim().InputFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OutputFrame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::VideoFrame>(this->shim().OutputFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::Effects::IVideoCompositor> : produce_base<D, winrt::Windows::Media::Effects::IVideoCompositor>
    {
        int32_t __stdcall get_TimeIndependent(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().TimeIndependent());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetEncodingProperties(void* backgroundProperties, void* device) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetEncodingProperties(*reinterpret_cast<winrt::Windows::Media::MediaProperties::VideoEncodingProperties const*>(&backgroundProperties), *reinterpret_cast<winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice const*>(&device));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CompositeFrame(void* context) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CompositeFrame(*reinterpret_cast<winrt::Windows::Media::Effects::CompositeVideoFrameContext const*>(&context));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Close(int32_t reason) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Close(*reinterpret_cast<winrt::Windows::Media::Effects::MediaEffectClosedReason const*>(&reason));
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
    };
    template <typename D>
    struct produce<D, winrt::Windows::Media::Effects::IVideoCompositorDefinition> : produce_base<D, winrt::Windows::Media::Effects::IVideoCompositorDefinition>
    {
        int32_t __stdcall get_ActivatableClassId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ActivatableClassId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IPropertySet>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Effects::IVideoCompositorDefinitionFactory> : produce_base<D, winrt::Windows::Media::Effects::IVideoCompositorDefinitionFactory>
    {
        int32_t __stdcall Create(void* activatableClassId, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Effects::VideoCompositorDefinition>(this->shim().Create(*reinterpret_cast<hstring const*>(&activatableClassId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithProperties(void* activatableClassId, void* props, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Effects::VideoCompositorDefinition>(this->shim().CreateWithProperties(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<winrt::Windows::Foundation::Collections::IPropertySet const*>(&props)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::Media::Effects::IVideoEffectDefinition> : produce_base<D, winrt::Windows::Media::Effects::IVideoEffectDefinition>
    {
        int32_t __stdcall get_ActivatableClassId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ActivatableClassId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Properties(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IPropertySet>(this->shim().Properties());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Effects::IVideoEffectDefinitionFactory> : produce_base<D, winrt::Windows::Media::Effects::IVideoEffectDefinitionFactory>
    {
        int32_t __stdcall Create(void* activatableClassId, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Effects::VideoEffectDefinition>(this->shim().Create(*reinterpret_cast<hstring const*>(&activatableClassId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateWithProperties(void* activatableClassId, void* props, void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Effects::VideoEffectDefinition>(this->shim().CreateWithProperties(*reinterpret_cast<hstring const*>(&activatableClassId), *reinterpret_cast<winrt::Windows::Foundation::Collections::IPropertySet const*>(&props)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Effects::IVideoTransformEffectDefinition> : produce_base<D, winrt::Windows::Media::Effects::IVideoTransformEffectDefinition>
    {
        int32_t __stdcall get_PaddingColor(struct struct_Windows_UI_Color* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Color>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Color>(this->shim().PaddingColor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PaddingColor(struct struct_Windows_UI_Color value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PaddingColor(*reinterpret_cast<winrt::Windows::UI::Color const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_OutputSize(winrt::Windows::Foundation::Size* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Size>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Size>(this->shim().OutputSize());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_OutputSize(winrt::Windows::Foundation::Size value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().OutputSize(*reinterpret_cast<winrt::Windows::Foundation::Size const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_CropRectangle(winrt::Windows::Foundation::Rect* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Rect>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Rect>(this->shim().CropRectangle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_CropRectangle(winrt::Windows::Foundation::Rect value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CropRectangle(*reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Rotation(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::MediaRotation>(this->shim().Rotation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Rotation(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Rotation(*reinterpret_cast<winrt::Windows::Media::MediaProperties::MediaRotation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Mirror(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::MediaMirroringOptions>(this->shim().Mirror());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Mirror(uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Mirror(*reinterpret_cast<winrt::Windows::Media::MediaProperties::MediaMirroringOptions const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ProcessingAlgorithm(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProcessingAlgorithm(*reinterpret_cast<winrt::Windows::Media::Transcoding::MediaVideoProcessingAlgorithm const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProcessingAlgorithm(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Transcoding::MediaVideoProcessingAlgorithm>(this->shim().ProcessingAlgorithm());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Effects::IVideoTransformEffectDefinition2> : produce_base<D, winrt::Windows::Media::Effects::IVideoTransformEffectDefinition2>
    {
        int32_t __stdcall get_SphericalProjection(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Effects::VideoTransformSphericalProjection>(this->shim().SphericalProjection());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Effects::IVideoTransformSphericalProjection> : produce_base<D, winrt::Windows::Media::Effects::IVideoTransformSphericalProjection>
    {
        int32_t __stdcall get_IsEnabled(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsEnabled());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsEnabled(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsEnabled(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FrameFormat(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::MediaProperties::SphericalVideoFrameFormat>(this->shim().FrameFormat());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_FrameFormat(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().FrameFormat(*reinterpret_cast<winrt::Windows::Media::MediaProperties::SphericalVideoFrameFormat const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ProjectionMode(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::Playback::SphericalVideoProjectionMode>(this->shim().ProjectionMode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ProjectionMode(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProjectionMode(*reinterpret_cast<winrt::Windows::Media::Playback::SphericalVideoProjectionMode const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_HorizontalFieldOfViewInDegrees(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().HorizontalFieldOfViewInDegrees());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_HorizontalFieldOfViewInDegrees(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().HorizontalFieldOfViewInDegrees(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ViewOrientation(winrt::Windows::Foundation::Numerics::quaternion* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Numerics::quaternion>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Numerics::quaternion>(this->shim().ViewOrientation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ViewOrientation(winrt::Windows::Foundation::Numerics::quaternion value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ViewOrientation(*reinterpret_cast<winrt::Windows::Foundation::Numerics::quaternion const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Media::Effects
{
    inline AudioEffectDefinition::AudioEffectDefinition(param::hstring const& activatableClassId) :
        AudioEffectDefinition(impl::call_factory<AudioEffectDefinition, IAudioEffectDefinitionFactory>([&](IAudioEffectDefinitionFactory const& f) { return f.Create(activatableClassId); }))
    {
    }
    inline AudioEffectDefinition::AudioEffectDefinition(param::hstring const& activatableClassId, winrt::Windows::Foundation::Collections::IPropertySet const& props) :
        AudioEffectDefinition(impl::call_factory<AudioEffectDefinition, IAudioEffectDefinitionFactory>([&](IAudioEffectDefinitionFactory const& f) { return f.CreateWithProperties(activatableClassId, props); }))
    {
    }
    inline auto AudioEffectsManager::CreateAudioRenderEffectsManager(param::hstring const& deviceId, winrt::Windows::Media::Render::AudioRenderCategory const& category)
    {
        return impl::call_factory<AudioEffectsManager, IAudioEffectsManagerStatics>([&](IAudioEffectsManagerStatics const& f) { return f.CreateAudioRenderEffectsManager(deviceId, category); });
    }
    inline auto AudioEffectsManager::CreateAudioRenderEffectsManager(param::hstring const& deviceId, winrt::Windows::Media::Render::AudioRenderCategory const& category, winrt::Windows::Media::AudioProcessing const& mode)
    {
        return impl::call_factory<AudioEffectsManager, IAudioEffectsManagerStatics>([&](IAudioEffectsManagerStatics const& f) { return f.CreateAudioRenderEffectsManager(deviceId, category, mode); });
    }
    inline auto AudioEffectsManager::CreateAudioCaptureEffectsManager(param::hstring const& deviceId, winrt::Windows::Media::Capture::MediaCategory const& category)
    {
        return impl::call_factory<AudioEffectsManager, IAudioEffectsManagerStatics>([&](IAudioEffectsManagerStatics const& f) { return f.CreateAudioCaptureEffectsManager(deviceId, category); });
    }
    inline auto AudioEffectsManager::CreateAudioCaptureEffectsManager(param::hstring const& deviceId, winrt::Windows::Media::Capture::MediaCategory const& category, winrt::Windows::Media::AudioProcessing const& mode)
    {
        return impl::call_factory<AudioEffectsManager, IAudioEffectsManagerStatics>([&](IAudioEffectsManagerStatics const& f) { return f.CreateAudioCaptureEffectsManager(deviceId, category, mode); });
    }
    inline VideoCompositorDefinition::VideoCompositorDefinition(param::hstring const& activatableClassId) :
        VideoCompositorDefinition(impl::call_factory<VideoCompositorDefinition, IVideoCompositorDefinitionFactory>([&](IVideoCompositorDefinitionFactory const& f) { return f.Create(activatableClassId); }))
    {
    }
    inline VideoCompositorDefinition::VideoCompositorDefinition(param::hstring const& activatableClassId, winrt::Windows::Foundation::Collections::IPropertySet const& props) :
        VideoCompositorDefinition(impl::call_factory<VideoCompositorDefinition, IVideoCompositorDefinitionFactory>([&](IVideoCompositorDefinitionFactory const& f) { return f.CreateWithProperties(activatableClassId, props); }))
    {
    }
    inline VideoEffectDefinition::VideoEffectDefinition(param::hstring const& activatableClassId) :
        VideoEffectDefinition(impl::call_factory<VideoEffectDefinition, IVideoEffectDefinitionFactory>([&](IVideoEffectDefinitionFactory const& f) { return f.Create(activatableClassId); }))
    {
    }
    inline VideoEffectDefinition::VideoEffectDefinition(param::hstring const& activatableClassId, winrt::Windows::Foundation::Collections::IPropertySet const& props) :
        VideoEffectDefinition(impl::call_factory<VideoEffectDefinition, IVideoEffectDefinitionFactory>([&](IVideoEffectDefinitionFactory const& f) { return f.CreateWithProperties(activatableClassId, props); }))
    {
    }
    inline VideoTransformEffectDefinition::VideoTransformEffectDefinition() :
        VideoTransformEffectDefinition(impl::call_factory_cast<VideoTransformEffectDefinition(*)(winrt::Windows::Foundation::IActivationFactory const&), VideoTransformEffectDefinition>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<VideoTransformEffectDefinition>(); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Media::Effects::IAudioCaptureEffectsManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::IAudioEffect> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::IAudioEffectDefinition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::IAudioEffectDefinitionFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::IAudioEffectsManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::IAudioRenderEffectsManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::IAudioRenderEffectsManager2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::IBasicAudioEffect> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::IBasicVideoEffect> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::ICompositeVideoFrameContext> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::IProcessAudioFrameContext> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::IProcessVideoFrameContext> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::IVideoCompositor> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::IVideoCompositorDefinition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::IVideoCompositorDefinitionFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::IVideoEffectDefinition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::IVideoEffectDefinitionFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::IVideoTransformEffectDefinition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::IVideoTransformEffectDefinition2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::IVideoTransformSphericalProjection> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::AudioCaptureEffectsManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::AudioEffect> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::AudioEffectDefinition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::AudioEffectsManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::AudioRenderEffectsManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::CompositeVideoFrameContext> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::ProcessAudioFrameContext> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::ProcessVideoFrameContext> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::VideoCompositorDefinition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::VideoEffectDefinition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::VideoTransformEffectDefinition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Effects::VideoTransformSphericalProjection> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
