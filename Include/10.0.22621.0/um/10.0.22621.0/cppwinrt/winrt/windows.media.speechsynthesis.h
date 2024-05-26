// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_SpeechSynthesis_H
#define WINRT_Windows_Media_SpeechSynthesis_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Media.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Media.2.h"
#include "winrt/impl/Windows.Media.Core.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.Media.SpeechSynthesis.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::SpeechSynthesis::VoiceInformation>) consume_Windows_Media_SpeechSynthesis_IInstalledVoicesStatic<D>::AllVoices() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechSynthesis::IInstalledVoicesStatic)->get_AllVoices(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::SpeechSynthesis::VoiceInformation>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechSynthesis::VoiceInformation) consume_Windows_Media_SpeechSynthesis_IInstalledVoicesStatic<D>::DefaultVoice() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechSynthesis::IInstalledVoicesStatic)->get_DefaultVoice(&value));
        return winrt::Windows::Media::SpeechSynthesis::VoiceInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_Media_SpeechSynthesis_IInstalledVoicesStatic2<D>::TrySetDefaultVoiceAsync(winrt::Windows::Media::SpeechSynthesis::VoiceInformation const& voice) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechSynthesis::IInstalledVoicesStatic2)->TrySetDefaultVoiceAsync(*(void**)(&voice), &result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::IMediaMarker>) consume_Windows_Media_SpeechSynthesis_ISpeechSynthesisStream<D>::Markers() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesisStream)->get_Markers(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::IMediaMarker>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::SpeechSynthesis::SpeechSynthesisStream>) consume_Windows_Media_SpeechSynthesis_ISpeechSynthesizer<D>::SynthesizeTextToStreamAsync(param::hstring const& text) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizer)->SynthesizeTextToStreamAsync(*(void**)(&text), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::SpeechSynthesis::SpeechSynthesisStream>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::SpeechSynthesis::SpeechSynthesisStream>) consume_Windows_Media_SpeechSynthesis_ISpeechSynthesizer<D>::SynthesizeSsmlToStreamAsync(param::hstring const& Ssml) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizer)->SynthesizeSsmlToStreamAsync(*(void**)(&Ssml), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::SpeechSynthesis::SpeechSynthesisStream>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_SpeechSynthesis_ISpeechSynthesizer<D>::Voice(winrt::Windows::Media::SpeechSynthesis::VoiceInformation const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizer)->put_Voice(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechSynthesis::VoiceInformation) consume_Windows_Media_SpeechSynthesis_ISpeechSynthesizer<D>::Voice() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizer)->get_Voice(&value));
        return winrt::Windows::Media::SpeechSynthesis::VoiceInformation{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechSynthesis::SpeechSynthesizerOptions) consume_Windows_Media_SpeechSynthesis_ISpeechSynthesizer2<D>::Options() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizer2)->get_Options(&value));
        return winrt::Windows::Media::SpeechSynthesis::SpeechSynthesizerOptions{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_SpeechSynthesis_ISpeechSynthesizerOptions<D>::IncludeWordBoundaryMetadata() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizerOptions)->get_IncludeWordBoundaryMetadata(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_SpeechSynthesis_ISpeechSynthesizerOptions<D>::IncludeWordBoundaryMetadata(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizerOptions)->put_IncludeWordBoundaryMetadata(value));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Media_SpeechSynthesis_ISpeechSynthesizerOptions<D>::IncludeSentenceBoundaryMetadata() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizerOptions)->get_IncludeSentenceBoundaryMetadata(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_SpeechSynthesis_ISpeechSynthesizerOptions<D>::IncludeSentenceBoundaryMetadata(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizerOptions)->put_IncludeSentenceBoundaryMetadata(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_SpeechSynthesis_ISpeechSynthesizerOptions2<D>::AudioVolume() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizerOptions2)->get_AudioVolume(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_SpeechSynthesis_ISpeechSynthesizerOptions2<D>::AudioVolume(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizerOptions2)->put_AudioVolume(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_SpeechSynthesis_ISpeechSynthesizerOptions2<D>::SpeakingRate() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizerOptions2)->get_SpeakingRate(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_SpeechSynthesis_ISpeechSynthesizerOptions2<D>::SpeakingRate(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizerOptions2)->put_SpeakingRate(value));
    }
    template <typename D> WINRT_IMPL_AUTO(double) consume_Windows_Media_SpeechSynthesis_ISpeechSynthesizerOptions2<D>::AudioPitch() const
    {
        double value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizerOptions2)->get_AudioPitch(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_SpeechSynthesis_ISpeechSynthesizerOptions2<D>::AudioPitch(double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizerOptions2)->put_AudioPitch(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechSynthesis::SpeechAppendedSilence) consume_Windows_Media_SpeechSynthesis_ISpeechSynthesizerOptions3<D>::AppendedSilence() const
    {
        winrt::Windows::Media::SpeechSynthesis::SpeechAppendedSilence value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizerOptions3)->get_AppendedSilence(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_SpeechSynthesis_ISpeechSynthesizerOptions3<D>::AppendedSilence(winrt::Windows::Media::SpeechSynthesis::SpeechAppendedSilence const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizerOptions3)->put_AppendedSilence(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechSynthesis::SpeechPunctuationSilence) consume_Windows_Media_SpeechSynthesis_ISpeechSynthesizerOptions3<D>::PunctuationSilence() const
    {
        winrt::Windows::Media::SpeechSynthesis::SpeechPunctuationSilence value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizerOptions3)->get_PunctuationSilence(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_SpeechSynthesis_ISpeechSynthesizerOptions3<D>::PunctuationSilence(winrt::Windows::Media::SpeechSynthesis::SpeechPunctuationSilence const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizerOptions3)->put_PunctuationSilence(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_SpeechSynthesis_IVoiceInformation<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechSynthesis::IVoiceInformation)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_SpeechSynthesis_IVoiceInformation<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechSynthesis::IVoiceInformation)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_SpeechSynthesis_IVoiceInformation<D>::Language() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechSynthesis::IVoiceInformation)->get_Language(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Media_SpeechSynthesis_IVoiceInformation<D>::Description() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechSynthesis::IVoiceInformation)->get_Description(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SpeechSynthesis::VoiceGender) consume_Windows_Media_SpeechSynthesis_IVoiceInformation<D>::Gender() const
    {
        winrt::Windows::Media::SpeechSynthesis::VoiceGender value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::SpeechSynthesis::IVoiceInformation)->get_Gender(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechSynthesis::IInstalledVoicesStatic> : produce_base<D, winrt::Windows::Media::SpeechSynthesis::IInstalledVoicesStatic>
    {
        int32_t __stdcall get_AllVoices(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::SpeechSynthesis::VoiceInformation>>(this->shim().AllVoices());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DefaultVoice(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SpeechSynthesis::VoiceInformation>(this->shim().DefaultVoice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechSynthesis::IInstalledVoicesStatic2> : produce_base<D, winrt::Windows::Media::SpeechSynthesis::IInstalledVoicesStatic2>
    {
        int32_t __stdcall TrySetDefaultVoiceAsync(void* voice, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().TrySetDefaultVoiceAsync(*reinterpret_cast<winrt::Windows::Media::SpeechSynthesis::VoiceInformation const*>(&voice)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesisStream> : produce_base<D, winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesisStream>
    {
        int32_t __stdcall get_Markers(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::IMediaMarker>>(this->shim().Markers());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizer> : produce_base<D, winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizer>
    {
        int32_t __stdcall SynthesizeTextToStreamAsync(void* text, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::SpeechSynthesis::SpeechSynthesisStream>>(this->shim().SynthesizeTextToStreamAsync(*reinterpret_cast<hstring const*>(&text)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SynthesizeSsmlToStreamAsync(void* Ssml, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Media::SpeechSynthesis::SpeechSynthesisStream>>(this->shim().SynthesizeSsmlToStreamAsync(*reinterpret_cast<hstring const*>(&Ssml)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Voice(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Voice(*reinterpret_cast<winrt::Windows::Media::SpeechSynthesis::VoiceInformation const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Voice(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SpeechSynthesis::VoiceInformation>(this->shim().Voice());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizer2> : produce_base<D, winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizer2>
    {
        int32_t __stdcall get_Options(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SpeechSynthesis::SpeechSynthesizerOptions>(this->shim().Options());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizerOptions> : produce_base<D, winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizerOptions>
    {
        int32_t __stdcall get_IncludeWordBoundaryMetadata(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IncludeWordBoundaryMetadata());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IncludeWordBoundaryMetadata(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IncludeWordBoundaryMetadata(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IncludeSentenceBoundaryMetadata(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IncludeSentenceBoundaryMetadata());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IncludeSentenceBoundaryMetadata(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IncludeSentenceBoundaryMetadata(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizerOptions2> : produce_base<D, winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizerOptions2>
    {
        int32_t __stdcall get_AudioVolume(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().AudioVolume());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AudioVolume(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AudioVolume(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SpeakingRate(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().SpeakingRate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SpeakingRate(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SpeakingRate(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AudioPitch(double* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<double>(this->shim().AudioPitch());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AudioPitch(double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AudioPitch(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizerOptions3> : produce_base<D, winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizerOptions3>
    {
        int32_t __stdcall get_AppendedSilence(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SpeechSynthesis::SpeechAppendedSilence>(this->shim().AppendedSilence());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AppendedSilence(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AppendedSilence(*reinterpret_cast<winrt::Windows::Media::SpeechSynthesis::SpeechAppendedSilence const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PunctuationSilence(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SpeechSynthesis::SpeechPunctuationSilence>(this->shim().PunctuationSilence());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PunctuationSilence(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PunctuationSilence(*reinterpret_cast<winrt::Windows::Media::SpeechSynthesis::SpeechPunctuationSilence const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::SpeechSynthesis::IVoiceInformation> : produce_base<D, winrt::Windows::Media::SpeechSynthesis::IVoiceInformation>
    {
        int32_t __stdcall get_DisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayName());
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
        int32_t __stdcall get_Language(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Language());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Description(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Description());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Gender(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SpeechSynthesis::VoiceGender>(this->shim().Gender());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Media::SpeechSynthesis
{
    inline SpeechSynthesizer::SpeechSynthesizer() :
        SpeechSynthesizer(impl::call_factory_cast<SpeechSynthesizer(*)(winrt::Windows::Foundation::IActivationFactory const&), SpeechSynthesizer>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SpeechSynthesizer>(); }))
    {
    }
    inline auto SpeechSynthesizer::AllVoices()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Media::SpeechSynthesis::VoiceInformation>(*)(IInstalledVoicesStatic const&), SpeechSynthesizer, IInstalledVoicesStatic>([](IInstalledVoicesStatic const& f) { return f.AllVoices(); });
    }
    inline auto SpeechSynthesizer::DefaultVoice()
    {
        return impl::call_factory_cast<winrt::Windows::Media::SpeechSynthesis::VoiceInformation(*)(IInstalledVoicesStatic const&), SpeechSynthesizer, IInstalledVoicesStatic>([](IInstalledVoicesStatic const& f) { return f.DefaultVoice(); });
    }
    inline auto SpeechSynthesizer::TrySetDefaultVoiceAsync(winrt::Windows::Media::SpeechSynthesis::VoiceInformation const& voice)
    {
        return impl::call_factory<SpeechSynthesizer, IInstalledVoicesStatic2>([&](IInstalledVoicesStatic2 const& f) { return f.TrySetDefaultVoiceAsync(voice); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Media::SpeechSynthesis::IInstalledVoicesStatic> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechSynthesis::IInstalledVoicesStatic2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesisStream> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizer2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizerOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizerOptions2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechSynthesis::ISpeechSynthesizerOptions3> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechSynthesis::IVoiceInformation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechSynthesis::SpeechSynthesisStream> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechSynthesis::SpeechSynthesizer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechSynthesis::SpeechSynthesizerOptions> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::SpeechSynthesis::VoiceInformation> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
