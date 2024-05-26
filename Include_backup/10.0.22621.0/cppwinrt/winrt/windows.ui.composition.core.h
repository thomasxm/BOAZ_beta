// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Composition_Core_H
#define WINRT_Windows_UI_Composition_Core_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.Composition.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.UI.Composition.2.h"
#include "winrt/impl/Windows.UI.Composition.Core.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Composition::Compositor) consume_Windows_UI_Composition_Core_ICompositorController<D>::Compositor() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Core::ICompositorController)->get_Compositor(&value));
        return winrt::Windows::UI::Composition::Compositor{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Core_ICompositorController<D>::Commit() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Core::ICompositorController)->Commit());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_UI_Composition_Core_ICompositorController<D>::EnsurePreviousCommitCompletedAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Core::ICompositorController)->EnsurePreviousCommitCompletedAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_UI_Composition_Core_ICompositorController<D>::CommitNeeded(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Composition::Core::CompositorController, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Core::ICompositorController)->add_CommitNeeded(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_UI_Composition_Core_ICompositorController<D>::CommitNeeded_revoker consume_Windows_UI_Composition_Core_ICompositorController<D>::CommitNeeded(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Composition::Core::CompositorController, winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, CommitNeeded_revoker>(this, CommitNeeded(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Composition_Core_ICompositorController<D>::CommitNeeded(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::UI::Composition::Core::ICompositorController)->remove_CommitNeeded(impl::bind_in(token));
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Composition::Core::ICompositorController> : produce_base<D, winrt::Windows::UI::Composition::Core::ICompositorController>
    {
        int32_t __stdcall get_Compositor(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Composition::Compositor>(this->shim().Compositor());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Commit() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Commit();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall EnsurePreviousCommitCompletedAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().EnsurePreviousCommitCompletedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_CommitNeeded(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().CommitNeeded(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Composition::Core::CompositorController, winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_CommitNeeded(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().CommitNeeded(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::UI::Composition::Core
{
    inline CompositorController::CompositorController() :
        CompositorController(impl::call_factory_cast<CompositorController(*)(winrt::Windows::Foundation::IActivationFactory const&), CompositorController>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<CompositorController>(); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Composition::Core::ICompositorController> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Composition::Core::CompositorController> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
