// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Input_Core_H
#define WINRT_Windows_UI_Input_Core_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.Input.h"
#include "winrt/impl/Windows.ApplicationModel.Core.2.h"
#include "winrt/impl/Windows.System.2.h"
#include "winrt/impl/Windows.UI.Core.2.h"
#include "winrt/impl/Windows.UI.Input.2.h"
#include "winrt/impl/Windows.UI.Input.Core.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::RadialController) consume_Windows_UI_Input_Core_IRadialControllerIndependentInputSource<D>::Controller() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSource)->get_Controller(&value));
        return winrt::Windows::UI::Input::RadialController{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreDispatcher) consume_Windows_UI_Input_Core_IRadialControllerIndependentInputSource<D>::Dispatcher() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSource)->get_Dispatcher(&value));
        return winrt::Windows::UI::Core::CoreDispatcher{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::System::DispatcherQueue) consume_Windows_UI_Input_Core_IRadialControllerIndependentInputSource2<D>::DispatcherQueue() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSource2)->get_DispatcherQueue(&value));
        return winrt::Windows::System::DispatcherQueue{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Input::Core::RadialControllerIndependentInputSource) consume_Windows_UI_Input_Core_IRadialControllerIndependentInputSourceStatics<D>::CreateForView(winrt::Windows::ApplicationModel::Core::CoreApplicationView const& view) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSourceStatics)->CreateForView(*(void**)(&view), &result));
        return winrt::Windows::UI::Input::Core::RadialControllerIndependentInputSource{ result, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSource> : produce_base<D, winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSource>
    {
        int32_t __stdcall get_Controller(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Input::RadialController>(this->shim().Controller());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Dispatcher(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Core::CoreDispatcher>(this->shim().Dispatcher());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSource2> : produce_base<D, winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSource2>
    {
        int32_t __stdcall get_DispatcherQueue(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::System::DispatcherQueue>(this->shim().DispatcherQueue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSourceStatics> : produce_base<D, winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSourceStatics>
    {
        int32_t __stdcall CreateForView(void* view, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Input::Core::RadialControllerIndependentInputSource>(this->shim().CreateForView(*reinterpret_cast<winrt::Windows::ApplicationModel::Core::CoreApplicationView const*>(&view)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::UI::Input::Core
{
    inline auto RadialControllerIndependentInputSource::CreateForView(winrt::Windows::ApplicationModel::Core::CoreApplicationView const& view)
    {
        return impl::call_factory<RadialControllerIndependentInputSource, IRadialControllerIndependentInputSourceStatics>([&](IRadialControllerIndependentInputSourceStatics const& f) { return f.CreateForView(view); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSource> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSource2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Core::IRadialControllerIndependentInputSourceStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Input::Core::RadialControllerIndependentInputSource> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
