// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Media_Core_Preview_H
#define WINRT_Windows_Media_Core_Preview_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Media.Core.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Media.2.h"
#include "winrt/impl/Windows.Media.Core.Preview.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Media::SoundLevel) consume_Windows_Media_Core_Preview_ISoundLevelBrokerStatics<D>::SoundLevel() const
    {
        winrt::Windows::Media::SoundLevel value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::Preview::ISoundLevelBrokerStatics)->get_SoundLevel(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Media_Core_Preview_ISoundLevelBrokerStatics<D>::SoundLevelChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Media::Core::Preview::ISoundLevelBrokerStatics)->add_SoundLevelChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Media_Core_Preview_ISoundLevelBrokerStatics<D>::SoundLevelChanged_revoker consume_Windows_Media_Core_Preview_ISoundLevelBrokerStatics<D>::SoundLevelChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const
    {
        return impl::make_event_revoker<D, SoundLevelChanged_revoker>(this, SoundLevelChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Media_Core_Preview_ISoundLevelBrokerStatics<D>::SoundLevelChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Media::Core::Preview::ISoundLevelBrokerStatics)->remove_SoundLevelChanged(impl::bind_in(token));
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Media::Core::Preview::ISoundLevelBrokerStatics> : produce_base<D, winrt::Windows::Media::Core::Preview::ISoundLevelBrokerStatics>
    {
        int32_t __stdcall get_SoundLevel(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Media::SoundLevel>(this->shim().SoundLevel());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_SoundLevelChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().SoundLevelChanged(*reinterpret_cast<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SoundLevelChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SoundLevelChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Media::Core::Preview
{
    inline auto SoundLevelBroker::SoundLevel()
    {
        return impl::call_factory_cast<winrt::Windows::Media::SoundLevel(*)(ISoundLevelBrokerStatics const&), SoundLevelBroker, ISoundLevelBrokerStatics>([](ISoundLevelBrokerStatics const& f) { return f.SoundLevel(); });
    }
    inline auto SoundLevelBroker::SoundLevelChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        return impl::call_factory<SoundLevelBroker, ISoundLevelBrokerStatics>([&](ISoundLevelBrokerStatics const& f) { return f.SoundLevelChanged(handler); });
    }
    inline SoundLevelBroker::SoundLevelChanged_revoker SoundLevelBroker::SoundLevelChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
    {
        auto f = get_activation_factory<SoundLevelBroker, winrt::Windows::Media::Core::Preview::ISoundLevelBrokerStatics>();
        return { f, f.SoundLevelChanged(handler) };
    }
    inline auto SoundLevelBroker::SoundLevelChanged(winrt::event_token const& token)
    {
        impl::call_factory<SoundLevelBroker, ISoundLevelBrokerStatics>([&](ISoundLevelBrokerStatics const& f) { return f.SoundLevelChanged(token); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Media::Core::Preview::ISoundLevelBrokerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Media::Core::Preview::SoundLevelBroker> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
