// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_CommunicationBlocking_H
#define WINRT_Windows_ApplicationModel_CommunicationBlocking_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.ApplicationModel.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.ApplicationModel.CommunicationBlocking.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_CommunicationBlocking_ICommunicationBlockingAccessManagerStatics<D>::IsBlockingActive() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics)->get_IsBlockingActive(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_CommunicationBlocking_ICommunicationBlockingAccessManagerStatics<D>::IsBlockedNumberAsync(param::hstring const& number) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics)->IsBlockedNumberAsync(*(void**)(&number), &result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_CommunicationBlocking_ICommunicationBlockingAccessManagerStatics<D>::ShowBlockNumbersUI(param::iterable<hstring> const& phoneNumbers) const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics)->ShowBlockNumbersUI(*(void**)(&phoneNumbers), &value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_CommunicationBlocking_ICommunicationBlockingAccessManagerStatics<D>::ShowUnblockNumbersUI(param::iterable<hstring> const& phoneNumbers) const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics)->ShowUnblockNumbersUI(*(void**)(&phoneNumbers), &value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_CommunicationBlocking_ICommunicationBlockingAccessManagerStatics<D>::ShowBlockedCallsUI() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics)->ShowBlockedCallsUI());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_CommunicationBlocking_ICommunicationBlockingAccessManagerStatics<D>::ShowBlockedMessagesUI() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics)->ShowBlockedMessagesUI());
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_ApplicationModel_CommunicationBlocking_ICommunicationBlockingAppManagerStatics<D>::IsCurrentAppActiveBlockingApp() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics)->get_IsCurrentAppActiveBlockingApp(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_CommunicationBlocking_ICommunicationBlockingAppManagerStatics<D>::ShowCommunicationBlockingSettingsUI() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics)->ShowCommunicationBlockingSettingsUI());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) consume_Windows_ApplicationModel_CommunicationBlocking_ICommunicationBlockingAppManagerStatics2<D>::RequestSetAsActiveBlockingAppAsync() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics2)->RequestSetAsActiveBlockingAppAsync(&result));
        return winrt::Windows::Foundation::IAsyncOperation<bool>{ result, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics> : produce_base<D, winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics>
    {
        int32_t __stdcall get_IsBlockingActive(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsBlockingActive());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall IsBlockedNumberAsync(void* number, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().IsBlockedNumberAsync(*reinterpret_cast<hstring const*>(&number)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShowBlockNumbersUI(void* phoneNumbers, bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ShowBlockNumbersUI(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&phoneNumbers)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShowUnblockNumbersUI(void* phoneNumbers, bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().ShowUnblockNumbersUI(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&phoneNumbers)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShowBlockedCallsUI() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowBlockedCallsUI();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShowBlockedMessagesUI() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowBlockedMessagesUI();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics> : produce_base<D, winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics>
    {
        int32_t __stdcall get_IsCurrentAppActiveBlockingApp(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCurrentAppActiveBlockingApp());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ShowCommunicationBlockingSettingsUI() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ShowCommunicationBlockingSettingsUI();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics2> : produce_base<D, winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics2>
    {
        int32_t __stdcall RequestSetAsActiveBlockingAppAsync(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IAsyncOperation<bool>>(this->shim().RequestSetAsActiveBlockingAppAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::CommunicationBlocking
{
    inline auto CommunicationBlockingAccessManager::IsBlockingActive()
    {
        return impl::call_factory_cast<bool(*)(ICommunicationBlockingAccessManagerStatics const&), CommunicationBlockingAccessManager, ICommunicationBlockingAccessManagerStatics>([](ICommunicationBlockingAccessManagerStatics const& f) { return f.IsBlockingActive(); });
    }
    inline auto CommunicationBlockingAccessManager::IsBlockedNumberAsync(param::hstring const& number)
    {
        return impl::call_factory<CommunicationBlockingAccessManager, ICommunicationBlockingAccessManagerStatics>([&](ICommunicationBlockingAccessManagerStatics const& f) { return f.IsBlockedNumberAsync(number); });
    }
    inline auto CommunicationBlockingAccessManager::ShowBlockNumbersUI(param::iterable<hstring> const& phoneNumbers)
    {
        return impl::call_factory<CommunicationBlockingAccessManager, ICommunicationBlockingAccessManagerStatics>([&](ICommunicationBlockingAccessManagerStatics const& f) { return f.ShowBlockNumbersUI(phoneNumbers); });
    }
    inline auto CommunicationBlockingAccessManager::ShowUnblockNumbersUI(param::iterable<hstring> const& phoneNumbers)
    {
        return impl::call_factory<CommunicationBlockingAccessManager, ICommunicationBlockingAccessManagerStatics>([&](ICommunicationBlockingAccessManagerStatics const& f) { return f.ShowUnblockNumbersUI(phoneNumbers); });
    }
    inline auto CommunicationBlockingAccessManager::ShowBlockedCallsUI()
    {
        impl::call_factory_cast<void(*)(ICommunicationBlockingAccessManagerStatics const&), CommunicationBlockingAccessManager, ICommunicationBlockingAccessManagerStatics>([](ICommunicationBlockingAccessManagerStatics const& f) { return f.ShowBlockedCallsUI(); });
    }
    inline auto CommunicationBlockingAccessManager::ShowBlockedMessagesUI()
    {
        impl::call_factory_cast<void(*)(ICommunicationBlockingAccessManagerStatics const&), CommunicationBlockingAccessManager, ICommunicationBlockingAccessManagerStatics>([](ICommunicationBlockingAccessManagerStatics const& f) { return f.ShowBlockedMessagesUI(); });
    }
    inline auto CommunicationBlockingAppManager::IsCurrentAppActiveBlockingApp()
    {
        return impl::call_factory_cast<bool(*)(ICommunicationBlockingAppManagerStatics const&), CommunicationBlockingAppManager, ICommunicationBlockingAppManagerStatics>([](ICommunicationBlockingAppManagerStatics const& f) { return f.IsCurrentAppActiveBlockingApp(); });
    }
    inline auto CommunicationBlockingAppManager::ShowCommunicationBlockingSettingsUI()
    {
        impl::call_factory_cast<void(*)(ICommunicationBlockingAppManagerStatics const&), CommunicationBlockingAppManager, ICommunicationBlockingAppManagerStatics>([](ICommunicationBlockingAppManagerStatics const& f) { return f.ShowCommunicationBlockingSettingsUI(); });
    }
    inline auto CommunicationBlockingAppManager::RequestSetAsActiveBlockingAppAsync()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::IAsyncOperation<bool>(*)(ICommunicationBlockingAppManagerStatics2 const&), CommunicationBlockingAppManager, ICommunicationBlockingAppManagerStatics2>([](ICommunicationBlockingAppManagerStatics2 const& f) { return f.RequestSetAsActiveBlockingAppAsync(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAccessManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::CommunicationBlocking::ICommunicationBlockingAppManagerStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::CommunicationBlocking::CommunicationBlockingAccessManager> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::CommunicationBlocking::CommunicationBlockingAppManager> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
