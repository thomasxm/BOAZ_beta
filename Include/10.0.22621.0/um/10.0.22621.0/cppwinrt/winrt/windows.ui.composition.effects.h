// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Composition_Effects_H
#define WINRT_Windows_UI_Composition_Effects_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.Composition.h"
#include "winrt/impl/Windows.Graphics.Effects.2.h"
#include "winrt/impl/Windows.UI.Composition.Effects.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Composition_Effects_ISceneLightingEffect<D>::AmbientAmount() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Effects::ISceneLightingEffect)->get_AmbientAmount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Effects_ISceneLightingEffect<D>::AmbientAmount(float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Effects::ISceneLightingEffect)->put_AmbientAmount(value));
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Composition_Effects_ISceneLightingEffect<D>::DiffuseAmount() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Effects::ISceneLightingEffect)->get_DiffuseAmount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Effects_ISceneLightingEffect<D>::DiffuseAmount(float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Effects::ISceneLightingEffect)->put_DiffuseAmount(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Effects::IGraphicsEffectSource) consume_Windows_UI_Composition_Effects_ISceneLightingEffect<D>::NormalMapSource() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Effects::ISceneLightingEffect)->get_NormalMapSource(&value));
        return winrt::Windows::Graphics::Effects::IGraphicsEffectSource{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Effects_ISceneLightingEffect<D>::NormalMapSource(winrt::Windows::Graphics::Effects::IGraphicsEffectSource const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Effects::ISceneLightingEffect)->put_NormalMapSource(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Composition_Effects_ISceneLightingEffect<D>::SpecularAmount() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Effects::ISceneLightingEffect)->get_SpecularAmount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Effects_ISceneLightingEffect<D>::SpecularAmount(float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Effects::ISceneLightingEffect)->put_SpecularAmount(value));
    }
    template <typename D> WINRT_IMPL_AUTO(float) consume_Windows_UI_Composition_Effects_ISceneLightingEffect<D>::SpecularShine() const
    {
        float value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Effects::ISceneLightingEffect)->get_SpecularShine(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Effects_ISceneLightingEffect<D>::SpecularShine(float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Effects::ISceneLightingEffect)->put_SpecularShine(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Effects::SceneLightingEffectReflectanceModel) consume_Windows_UI_Composition_Effects_ISceneLightingEffect2<D>::ReflectanceModel() const
    {
        winrt::Windows::UI::Composition::Effects::SceneLightingEffectReflectanceModel value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Effects::ISceneLightingEffect2)->get_ReflectanceModel(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Effects_ISceneLightingEffect2<D>::ReflectanceModel(winrt::Windows::UI::Composition::Effects::SceneLightingEffectReflectanceModel const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Effects::ISceneLightingEffect2)->put_ReflectanceModel(static_cast<int32_t>(value)));
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Effects::ISceneLightingEffect> : produce_base<D, winrt::Windows::UI::Composition::Effects::ISceneLightingEffect>
    {
        int32_t __stdcall get_AmbientAmount(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().AmbientAmount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_AmbientAmount(float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AmbientAmount(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DiffuseAmount(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().DiffuseAmount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_DiffuseAmount(float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DiffuseAmount(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NormalMapSource(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Effects::IGraphicsEffectSource>(this->shim().NormalMapSource());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_NormalMapSource(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NormalMapSource(*reinterpret_cast<winrt::Windows::Graphics::Effects::IGraphicsEffectSource const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SpecularAmount(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().SpecularAmount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SpecularAmount(float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SpecularAmount(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SpecularShine(float* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<float>(this->shim().SpecularShine());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_SpecularShine(float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SpecularShine(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Effects::ISceneLightingEffect2> : produce_base<D, winrt::Windows::UI::Composition::Effects::ISceneLightingEffect2>
    {
        int32_t __stdcall get_ReflectanceModel(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::Effects::SceneLightingEffectReflectanceModel>(this->shim().ReflectanceModel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_ReflectanceModel(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReflectanceModel(*reinterpret_cast<winrt::Windows::UI::Composition::Effects::SceneLightingEffectReflectanceModel const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::UI::Composition::Effects
{
    inline SceneLightingEffect::SceneLightingEffect() :
        SceneLightingEffect(impl::call_factory_cast<SceneLightingEffect(*)(winrt::Windows::Foundation::IActivationFactory const&), SceneLightingEffect>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<SceneLightingEffect>(); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Composition::Effects::ISceneLightingEffect> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Effects::ISceneLightingEffect2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Effects::SceneLightingEffect> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
