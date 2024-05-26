// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Haptics_H
#define WINRT_Windows_Devices_Haptics_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Devices.Haptics.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Haptics_IKnownSimpleHapticsControllerWaveformsStatics<D>::Click() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics)->get_Click(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Haptics_IKnownSimpleHapticsControllerWaveformsStatics<D>::BuzzContinuous() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics)->get_BuzzContinuous(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Haptics_IKnownSimpleHapticsControllerWaveformsStatics<D>::RumbleContinuous() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics)->get_RumbleContinuous(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Haptics_IKnownSimpleHapticsControllerWaveformsStatics<D>::Press() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics)->get_Press(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Haptics_IKnownSimpleHapticsControllerWaveformsStatics<D>::Release() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics)->get_Release(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Haptics_IKnownSimpleHapticsControllerWaveformsStatics2<D>::BrushContinuous() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics2)->get_BrushContinuous(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Haptics_IKnownSimpleHapticsControllerWaveformsStatics2<D>::ChiselMarkerContinuous() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics2)->get_ChiselMarkerContinuous(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Haptics_IKnownSimpleHapticsControllerWaveformsStatics2<D>::EraserContinuous() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics2)->get_EraserContinuous(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Haptics_IKnownSimpleHapticsControllerWaveformsStatics2<D>::Error() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics2)->get_Error(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Haptics_IKnownSimpleHapticsControllerWaveformsStatics2<D>::GalaxyPenContinuous() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics2)->get_GalaxyPenContinuous(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Haptics_IKnownSimpleHapticsControllerWaveformsStatics2<D>::Hover() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics2)->get_Hover(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Haptics_IKnownSimpleHapticsControllerWaveformsStatics2<D>::InkContinuous() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics2)->get_InkContinuous(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Haptics_IKnownSimpleHapticsControllerWaveformsStatics2<D>::MarkerContinuous() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics2)->get_MarkerContinuous(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Haptics_IKnownSimpleHapticsControllerWaveformsStatics2<D>::PencilContinuous() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics2)->get_PencilContinuous(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Haptics_IKnownSimpleHapticsControllerWaveformsStatics2<D>::Success() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics2)->get_Success(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Haptics_ISimpleHapticsController<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::ISimpleHapticsController)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Haptics::SimpleHapticsControllerFeedback>) consume_Windows_Devices_Haptics_ISimpleHapticsController<D>::SupportedFeedback() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::ISimpleHapticsController)->get_SupportedFeedback(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Haptics::SimpleHapticsControllerFeedback>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Haptics_ISimpleHapticsController<D>::IsIntensitySupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::ISimpleHapticsController)->get_IsIntensitySupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Haptics_ISimpleHapticsController<D>::IsPlayCountSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::ISimpleHapticsController)->get_IsPlayCountSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Haptics_ISimpleHapticsController<D>::IsPlayDurationSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::ISimpleHapticsController)->get_IsPlayDurationSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Haptics_ISimpleHapticsController<D>::IsReplayPauseIntervalSupported() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::ISimpleHapticsController)->get_IsReplayPauseIntervalSupported(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Haptics_ISimpleHapticsController<D>::StopFeedback() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::ISimpleHapticsController)->StopFeedback());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Haptics_ISimpleHapticsController<D>::SendHapticFeedback(winrt::Windows::Devices::Haptics::SimpleHapticsControllerFeedback const& feedback) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::ISimpleHapticsController)->SendHapticFeedback(*(void**)(&feedback)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Haptics_ISimpleHapticsController<D>::SendHapticFeedback(winrt::Windows::Devices::Haptics::SimpleHapticsControllerFeedback const& feedback, double intensity) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::ISimpleHapticsController)->SendHapticFeedbackWithIntensity(*(void**)(&feedback), intensity));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Haptics_ISimpleHapticsController<D>::SendHapticFeedbackForDuration(winrt::Windows::Devices::Haptics::SimpleHapticsControllerFeedback const& feedback, double intensity, winrt::Windows::Foundation::TimeSpan const& playDuration) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::ISimpleHapticsController)->SendHapticFeedbackForDuration(*(void**)(&feedback), intensity, impl::bind_in(playDuration)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Haptics_ISimpleHapticsController<D>::SendHapticFeedbackForPlayCount(winrt::Windows::Devices::Haptics::SimpleHapticsControllerFeedback const& feedback, double intensity, int32_t playCount, winrt::Windows::Foundation::TimeSpan const& replayPauseInterval) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::ISimpleHapticsController)->SendHapticFeedbackForPlayCount(*(void**)(&feedback), intensity, playCount, impl::bind_in(replayPauseInterval)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint16_t) consume_Windows_Devices_Haptics_ISimpleHapticsControllerFeedback<D>::Waveform() const
    {
        uint16_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::ISimpleHapticsControllerFeedback)->get_Waveform(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_Devices_Haptics_ISimpleHapticsControllerFeedback<D>::Duration() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::ISimpleHapticsControllerFeedback)->get_Duration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Haptics_IVibrationDevice<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::IVibrationDevice)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Haptics::SimpleHapticsController) consume_Windows_Devices_Haptics_IVibrationDevice<D>::SimpleHapticsController() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::IVibrationDevice)->get_SimpleHapticsController(&value));
        return winrt::Windows::Devices::Haptics::SimpleHapticsController{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Haptics::VibrationAccessStatus>) consume_Windows_Devices_Haptics_IVibrationDeviceStatics<D>::RequestAccessAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::IVibrationDeviceStatics)->RequestAccessAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Haptics::VibrationAccessStatus>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Haptics_IVibrationDeviceStatics<D>::GetDeviceSelector() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::IVibrationDeviceStatics)->GetDeviceSelector(&result));
        return hstring{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Haptics::VibrationDevice>) consume_Windows_Devices_Haptics_IVibrationDeviceStatics<D>::FromIdAsync(param::hstring const& deviceId) const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::IVibrationDeviceStatics)->FromIdAsync(*(void**)(&deviceId), &operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Haptics::VibrationDevice>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Haptics::VibrationDevice>) consume_Windows_Devices_Haptics_IVibrationDeviceStatics<D>::GetDefaultAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::IVibrationDeviceStatics)->GetDefaultAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Haptics::VibrationDevice>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Haptics::VibrationDevice>>) consume_Windows_Devices_Haptics_IVibrationDeviceStatics<D>::FindAllAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Haptics::IVibrationDeviceStatics)->FindAllAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Haptics::VibrationDevice>>{ operation, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics> : produce_base<D, winrt::Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics>
    {
        int32_t __stdcall get_Click(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Click());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_BuzzContinuous(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().BuzzContinuous());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RumbleContinuous(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().RumbleContinuous());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Press(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Press());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Release(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Release());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics2> : produce_base<D, winrt::Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics2>
    {
        int32_t __stdcall get_BrushContinuous(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().BrushContinuous());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ChiselMarkerContinuous(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().ChiselMarkerContinuous());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EraserContinuous(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().EraserContinuous());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Error(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Error());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_GalaxyPenContinuous(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().GalaxyPenContinuous());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Hover(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Hover());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InkContinuous(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().InkContinuous());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_MarkerContinuous(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().MarkerContinuous());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PencilContinuous(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().PencilContinuous());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Success(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Success());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Haptics::ISimpleHapticsController> : produce_base<D, winrt::Windows::Devices::Haptics::ISimpleHapticsController>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SupportedFeedback(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Haptics::SimpleHapticsControllerFeedback>>(this->shim().SupportedFeedback());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsIntensitySupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsIntensitySupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPlayCountSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPlayCountSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPlayDurationSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPlayDurationSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsReplayPauseIntervalSupported(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsReplayPauseIntervalSupported());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StopFeedback() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().StopFeedback();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SendHapticFeedback(void* feedback) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SendHapticFeedback(*reinterpret_cast<winrt::Windows::Devices::Haptics::SimpleHapticsControllerFeedback const*>(&feedback));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SendHapticFeedbackWithIntensity(void* feedback, double intensity) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SendHapticFeedback(*reinterpret_cast<winrt::Windows::Devices::Haptics::SimpleHapticsControllerFeedback const*>(&feedback), intensity);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SendHapticFeedbackForDuration(void* feedback, double intensity, int64_t playDuration) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SendHapticFeedbackForDuration(*reinterpret_cast<winrt::Windows::Devices::Haptics::SimpleHapticsControllerFeedback const*>(&feedback), intensity, *reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&playDuration));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SendHapticFeedbackForPlayCount(void* feedback, double intensity, int32_t playCount, int64_t replayPauseInterval) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SendHapticFeedbackForPlayCount(*reinterpret_cast<winrt::Windows::Devices::Haptics::SimpleHapticsControllerFeedback const*>(&feedback), intensity, playCount, *reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&replayPauseInterval));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Haptics::ISimpleHapticsControllerFeedback> : produce_base<D, winrt::Windows::Devices::Haptics::ISimpleHapticsControllerFeedback>
    {
        int32_t __stdcall get_Waveform(uint16_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint16_t>(this->shim().Waveform());
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
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Haptics::IVibrationDevice> : produce_base<D, winrt::Windows::Devices::Haptics::IVibrationDevice>
    {
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SimpleHapticsController(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Haptics::SimpleHapticsController>(this->shim().SimpleHapticsController());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Haptics::IVibrationDeviceStatics> : produce_base<D, winrt::Windows::Devices::Haptics::IVibrationDeviceStatics>
    {
        int32_t __stdcall RequestAccessAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Haptics::VibrationAccessStatus>>(this->shim().RequestAccessAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeviceSelector(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<hstring>(this->shim().GetDeviceSelector());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FromIdAsync(void* deviceId, void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Haptics::VibrationDevice>>(this->shim().FromIdAsync(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDefaultAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Haptics::VibrationDevice>>(this->shim().GetDefaultAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall FindAllAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Haptics::VibrationDevice>>>(this->shim().FindAllAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Devices::Haptics
{
    inline auto KnownSimpleHapticsControllerWaveforms::Click()
    {
        return impl::call_factory_cast<uint16_t(*)(IKnownSimpleHapticsControllerWaveformsStatics const&), KnownSimpleHapticsControllerWaveforms, IKnownSimpleHapticsControllerWaveformsStatics>([](IKnownSimpleHapticsControllerWaveformsStatics const& f) { return f.Click(); });
    }
    inline auto KnownSimpleHapticsControllerWaveforms::BuzzContinuous()
    {
        return impl::call_factory_cast<uint16_t(*)(IKnownSimpleHapticsControllerWaveformsStatics const&), KnownSimpleHapticsControllerWaveforms, IKnownSimpleHapticsControllerWaveformsStatics>([](IKnownSimpleHapticsControllerWaveformsStatics const& f) { return f.BuzzContinuous(); });
    }
    inline auto KnownSimpleHapticsControllerWaveforms::RumbleContinuous()
    {
        return impl::call_factory_cast<uint16_t(*)(IKnownSimpleHapticsControllerWaveformsStatics const&), KnownSimpleHapticsControllerWaveforms, IKnownSimpleHapticsControllerWaveformsStatics>([](IKnownSimpleHapticsControllerWaveformsStatics const& f) { return f.RumbleContinuous(); });
    }
    inline auto KnownSimpleHapticsControllerWaveforms::Press()
    {
        return impl::call_factory_cast<uint16_t(*)(IKnownSimpleHapticsControllerWaveformsStatics const&), KnownSimpleHapticsControllerWaveforms, IKnownSimpleHapticsControllerWaveformsStatics>([](IKnownSimpleHapticsControllerWaveformsStatics const& f) { return f.Press(); });
    }
    inline auto KnownSimpleHapticsControllerWaveforms::Release()
    {
        return impl::call_factory_cast<uint16_t(*)(IKnownSimpleHapticsControllerWaveformsStatics const&), KnownSimpleHapticsControllerWaveforms, IKnownSimpleHapticsControllerWaveformsStatics>([](IKnownSimpleHapticsControllerWaveformsStatics const& f) { return f.Release(); });
    }
    inline auto KnownSimpleHapticsControllerWaveforms::BrushContinuous()
    {
        return impl::call_factory_cast<uint16_t(*)(IKnownSimpleHapticsControllerWaveformsStatics2 const&), KnownSimpleHapticsControllerWaveforms, IKnownSimpleHapticsControllerWaveformsStatics2>([](IKnownSimpleHapticsControllerWaveformsStatics2 const& f) { return f.BrushContinuous(); });
    }
    inline auto KnownSimpleHapticsControllerWaveforms::ChiselMarkerContinuous()
    {
        return impl::call_factory_cast<uint16_t(*)(IKnownSimpleHapticsControllerWaveformsStatics2 const&), KnownSimpleHapticsControllerWaveforms, IKnownSimpleHapticsControllerWaveformsStatics2>([](IKnownSimpleHapticsControllerWaveformsStatics2 const& f) { return f.ChiselMarkerContinuous(); });
    }
    inline auto KnownSimpleHapticsControllerWaveforms::EraserContinuous()
    {
        return impl::call_factory_cast<uint16_t(*)(IKnownSimpleHapticsControllerWaveformsStatics2 const&), KnownSimpleHapticsControllerWaveforms, IKnownSimpleHapticsControllerWaveformsStatics2>([](IKnownSimpleHapticsControllerWaveformsStatics2 const& f) { return f.EraserContinuous(); });
    }
    inline auto KnownSimpleHapticsControllerWaveforms::Error()
    {
        return impl::call_factory_cast<uint16_t(*)(IKnownSimpleHapticsControllerWaveformsStatics2 const&), KnownSimpleHapticsControllerWaveforms, IKnownSimpleHapticsControllerWaveformsStatics2>([](IKnownSimpleHapticsControllerWaveformsStatics2 const& f) { return f.Error(); });
    }
    inline auto KnownSimpleHapticsControllerWaveforms::GalaxyPenContinuous()
    {
        return impl::call_factory_cast<uint16_t(*)(IKnownSimpleHapticsControllerWaveformsStatics2 const&), KnownSimpleHapticsControllerWaveforms, IKnownSimpleHapticsControllerWaveformsStatics2>([](IKnownSimpleHapticsControllerWaveformsStatics2 const& f) { return f.GalaxyPenContinuous(); });
    }
    inline auto KnownSimpleHapticsControllerWaveforms::Hover()
    {
        return impl::call_factory_cast<uint16_t(*)(IKnownSimpleHapticsControllerWaveformsStatics2 const&), KnownSimpleHapticsControllerWaveforms, IKnownSimpleHapticsControllerWaveformsStatics2>([](IKnownSimpleHapticsControllerWaveformsStatics2 const& f) { return f.Hover(); });
    }
    inline auto KnownSimpleHapticsControllerWaveforms::InkContinuous()
    {
        return impl::call_factory_cast<uint16_t(*)(IKnownSimpleHapticsControllerWaveformsStatics2 const&), KnownSimpleHapticsControllerWaveforms, IKnownSimpleHapticsControllerWaveformsStatics2>([](IKnownSimpleHapticsControllerWaveformsStatics2 const& f) { return f.InkContinuous(); });
    }
    inline auto KnownSimpleHapticsControllerWaveforms::MarkerContinuous()
    {
        return impl::call_factory_cast<uint16_t(*)(IKnownSimpleHapticsControllerWaveformsStatics2 const&), KnownSimpleHapticsControllerWaveforms, IKnownSimpleHapticsControllerWaveformsStatics2>([](IKnownSimpleHapticsControllerWaveformsStatics2 const& f) { return f.MarkerContinuous(); });
    }
    inline auto KnownSimpleHapticsControllerWaveforms::PencilContinuous()
    {
        return impl::call_factory_cast<uint16_t(*)(IKnownSimpleHapticsControllerWaveformsStatics2 const&), KnownSimpleHapticsControllerWaveforms, IKnownSimpleHapticsControllerWaveformsStatics2>([](IKnownSimpleHapticsControllerWaveformsStatics2 const& f) { return f.PencilContinuous(); });
    }
    inline auto KnownSimpleHapticsControllerWaveforms::Success()
    {
        return impl::call_factory_cast<uint16_t(*)(IKnownSimpleHapticsControllerWaveformsStatics2 const&), KnownSimpleHapticsControllerWaveforms, IKnownSimpleHapticsControllerWaveformsStatics2>([](IKnownSimpleHapticsControllerWaveformsStatics2 const& f) { return f.Success(); });
    }
    inline auto VibrationDevice::RequestAccessAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Haptics::VibrationAccessStatus>(*)(IVibrationDeviceStatics const&), VibrationDevice, IVibrationDeviceStatics>([](IVibrationDeviceStatics const& f) { return f.RequestAccessAsync(); });
    }
    inline auto VibrationDevice::GetDeviceSelector()
    {
        return impl::call_factory_cast<hstring(*)(IVibrationDeviceStatics const&), VibrationDevice, IVibrationDeviceStatics>([](IVibrationDeviceStatics const& f) { return f.GetDeviceSelector(); });
    }
    inline auto VibrationDevice::FromIdAsync(param::hstring const& deviceId)
    {
        return impl::call_factory<VibrationDevice, IVibrationDeviceStatics>([&](IVibrationDeviceStatics const& f) { return f.FromIdAsync(deviceId); });
    }
    inline auto VibrationDevice::GetDefaultAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Haptics::VibrationDevice>(*)(IVibrationDeviceStatics const&), VibrationDevice, IVibrationDeviceStatics>([](IVibrationDeviceStatics const& f) { return f.GetDefaultAsync(); });
    }
    inline auto VibrationDevice::FindAllAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Haptics::VibrationDevice>>(*)(IVibrationDeviceStatics const&), VibrationDevice, IVibrationDeviceStatics>([](IVibrationDeviceStatics const& f) { return f.FindAllAsync(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Haptics::IKnownSimpleHapticsControllerWaveformsStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Haptics::ISimpleHapticsController> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Haptics::ISimpleHapticsControllerFeedback> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Haptics::IVibrationDevice> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Haptics::IVibrationDeviceStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Haptics::KnownSimpleHapticsControllerWaveforms> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Haptics::SimpleHapticsController> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Haptics::SimpleHapticsControllerFeedback> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Haptics::VibrationDevice> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
