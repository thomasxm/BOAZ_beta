// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Core_AnimationMetrics_H
#define WINRT_Windows_UI_Core_AnimationMetrics_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.Core.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.UI.Core.AnimationMetrics.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Core::AnimationMetrics::IPropertyAnimation>) consume_Windows_UI_Core_AnimationMetrics_IAnimationDescription<D>::Animations() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::AnimationMetrics::IAnimationDescription)->get_Animations(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Core::AnimationMetrics::IPropertyAnimation>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_UI_Core_AnimationMetrics_IAnimationDescription<D>::StaggerDelay() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::AnimationMetrics::IAnimationDescription)->get_StaggerDelay(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Core_AnimationMetrics_IAnimationDescription<D>::StaggerDelayFactor() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::AnimationMetrics::IAnimationDescription)->get_StaggerDelayFactor(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_UI_Core_AnimationMetrics_IAnimationDescription<D>::DelayLimit() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::AnimationMetrics::IAnimationDescription)->get_DelayLimit(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_UI_Core_AnimationMetrics_IAnimationDescription<D>::ZOrder() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::AnimationMetrics::IAnimationDescription)->get_ZOrder(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::AnimationMetrics::AnimationDescription) consume_Windows_UI_Core_AnimationMetrics_IAnimationDescriptionFactory<D>::CreateInstance(winrt::Windows::UI::Core::AnimationMetrics::AnimationEffect const& effect, winrt::Windows::UI::Core::AnimationMetrics::AnimationEffectTarget const& target) const
    {
        void* animation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::AnimationMetrics::IAnimationDescriptionFactory)->CreateInstance(static_cast<int32_t>(effect), static_cast<int32_t>(target), &animation));
        return winrt::Windows::UI::Core::AnimationMetrics::AnimationDescription{ animation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<float>) consume_Windows_UI_Core_AnimationMetrics_IOpacityAnimation<D>::InitialOpacity() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::AnimationMetrics::IOpacityAnimation)->get_InitialOpacity(&value));
        return winrt::Windows::Foundation::IReference<float>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Core_AnimationMetrics_IOpacityAnimation<D>::FinalOpacity() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::AnimationMetrics::IOpacityAnimation)->get_FinalOpacity(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::AnimationMetrics::PropertyAnimationType) consume_Windows_UI_Core_AnimationMetrics_IPropertyAnimation<D>::Type() const
    {
        winrt::Windows::UI::Core::AnimationMetrics::PropertyAnimationType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::AnimationMetrics::IPropertyAnimation)->get_Type(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_UI_Core_AnimationMetrics_IPropertyAnimation<D>::Delay() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::AnimationMetrics::IPropertyAnimation)->get_Delay(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) consume_Windows_UI_Core_AnimationMetrics_IPropertyAnimation<D>::Duration() const
    {
        winrt::Windows::Foundation::TimeSpan value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::AnimationMetrics::IPropertyAnimation)->get_Duration(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Core_AnimationMetrics_IPropertyAnimation<D>::Control1() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::AnimationMetrics::IPropertyAnimation)->get_Control1(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Core_AnimationMetrics_IPropertyAnimation<D>::Control2() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::AnimationMetrics::IPropertyAnimation)->get_Control2(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<float>) consume_Windows_UI_Core_AnimationMetrics_IScaleAnimation<D>::InitialScaleX() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::AnimationMetrics::IScaleAnimation)->get_InitialScaleX(&value));
        return winrt::Windows::Foundation::IReference<float>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<float>) consume_Windows_UI_Core_AnimationMetrics_IScaleAnimation<D>::InitialScaleY() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::AnimationMetrics::IScaleAnimation)->get_InitialScaleY(&value));
        return winrt::Windows::Foundation::IReference<float>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Core_AnimationMetrics_IScaleAnimation<D>::FinalScaleX() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::AnimationMetrics::IScaleAnimation)->get_FinalScaleX(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Core_AnimationMetrics_IScaleAnimation<D>::FinalScaleY() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::AnimationMetrics::IScaleAnimation)->get_FinalScaleY(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) consume_Windows_UI_Core_AnimationMetrics_IScaleAnimation<D>::NormalizedOrigin() const
    {
        winrt::Windows::Foundation::Point value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Core::AnimationMetrics::IScaleAnimation)->get_NormalizedOrigin(put_abi(value)));
        return value;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::AnimationMetrics::IAnimationDescription> : produce_base<D, winrt::Windows::UI::Core::AnimationMetrics::IAnimationDescription>
    {
        int32_t __stdcall get_Animations(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::Core::AnimationMetrics::IPropertyAnimation>>(this->shim().Animations());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StaggerDelay(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().StaggerDelay());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_StaggerDelayFactor(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().StaggerDelayFactor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DelayLimit(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().DelayLimit());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ZOrder(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().ZOrder());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::AnimationMetrics::IAnimationDescriptionFactory> : produce_base<D, winrt::Windows::UI::Core::AnimationMetrics::IAnimationDescriptionFactory>
    {
        int32_t __stdcall CreateInstance(int32_t effect, int32_t target, void** animation) noexcept final try
        {
            clear_abi(animation);
            typename D::abi_guard guard(this->shim());
            *animation = detach_from<winrt::Windows::UI::Core::AnimationMetrics::AnimationDescription>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::UI::Core::AnimationMetrics::AnimationEffect const*>(&effect), *reinterpret_cast<winrt::Windows::UI::Core::AnimationMetrics::AnimationEffectTarget const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::AnimationMetrics::IOpacityAnimation> : produce_base<D, winrt::Windows::UI::Core::AnimationMetrics::IOpacityAnimation>
    {
        int32_t __stdcall get_InitialOpacity(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<float>>(this->shim().InitialOpacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FinalOpacity(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().FinalOpacity());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::AnimationMetrics::IPropertyAnimation> : produce_base<D, winrt::Windows::UI::Core::AnimationMetrics::IPropertyAnimation>
    {
        int32_t __stdcall get_Type(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Core::AnimationMetrics::PropertyAnimationType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Delay(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::TimeSpan>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::TimeSpan>(this->shim().Delay());
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
        int32_t __stdcall get_Control1(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().Control1());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Control2(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().Control2());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Core::AnimationMetrics::IScaleAnimation> : produce_base<D, winrt::Windows::UI::Core::AnimationMetrics::IScaleAnimation>
    {
        int32_t __stdcall get_InitialScaleX(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<float>>(this->shim().InitialScaleX());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InitialScaleY(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<float>>(this->shim().InitialScaleY());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FinalScaleX(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().FinalScaleX());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FinalScaleY(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().FinalScaleY());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NormalizedOrigin(winrt::Windows::Foundation::Point* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::Point>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Point>(this->shim().NormalizedOrigin());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::UI::Core::AnimationMetrics
{
    inline AnimationDescription::AnimationDescription(winrt::Windows::UI::Core::AnimationMetrics::AnimationEffect const& effect, winrt::Windows::UI::Core::AnimationMetrics::AnimationEffectTarget const& target) :
        AnimationDescription(impl::call_factory<AnimationDescription, IAnimationDescriptionFactory>([&](IAnimationDescriptionFactory const& f) { return f.CreateInstance(effect, target); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Core::AnimationMetrics::IAnimationDescription> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::AnimationMetrics::IAnimationDescriptionFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::AnimationMetrics::IOpacityAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::AnimationMetrics::IPropertyAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::AnimationMetrics::IScaleAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::AnimationMetrics::AnimationDescription> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::AnimationMetrics::OpacityAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::AnimationMetrics::PropertyAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::AnimationMetrics::ScaleAnimation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Core::AnimationMetrics::TranslationAnimation> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
