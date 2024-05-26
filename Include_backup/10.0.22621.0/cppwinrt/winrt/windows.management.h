// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Management_H
#define WINRT_Windows_Management_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Management.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Management_IMdmAlert<D>::Data() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::IMdmAlert)->get_Data(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Management_IMdmAlert<D>::Data(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::IMdmAlert)->put_Data(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Management::MdmAlertDataType) consume_Windows_Management_IMdmAlert<D>::Format() const
    {
        winrt::Windows::Management::MdmAlertDataType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::IMdmAlert)->get_Format(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Management_IMdmAlert<D>::Format(winrt::Windows::Management::MdmAlertDataType const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::IMdmAlert)->put_Format(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Management::MdmAlertMark) consume_Windows_Management_IMdmAlert<D>::Mark() const
    {
        winrt::Windows::Management::MdmAlertMark value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::IMdmAlert)->get_Mark(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Management_IMdmAlert<D>::Mark(winrt::Windows::Management::MdmAlertMark const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::IMdmAlert)->put_Mark(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Management_IMdmAlert<D>::Source() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::IMdmAlert)->get_Source(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Management_IMdmAlert<D>::Source(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::IMdmAlert)->put_Source(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Management_IMdmAlert<D>::Status() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::IMdmAlert)->get_Status(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Management_IMdmAlert<D>::Target() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::IMdmAlert)->get_Target(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Management_IMdmAlert<D>::Target(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::IMdmAlert)->put_Target(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Management_IMdmAlert<D>::Type() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::IMdmAlert)->get_Type(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Management_IMdmAlert<D>::Type(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::IMdmAlert)->put_Type(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Management::MdmAlert>) consume_Windows_Management_IMdmSession<D>::Alerts() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::IMdmSession)->get_Alerts(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Management::MdmAlert>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Management_IMdmSession<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::IMdmSession)->get_ExtendedError(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Management_IMdmSession<D>::Id() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::IMdmSession)->get_Id(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Management::MdmSessionState) consume_Windows_Management_IMdmSession<D>::State() const
    {
        winrt::Windows::Management::MdmSessionState value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::IMdmSession)->get_State(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Management_IMdmSession<D>::AttachAsync() const
    {
        void* action{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::IMdmSession)->AttachAsync(&action));
        return winrt::Windows::Foundation::IAsyncAction{ action, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Management_IMdmSession<D>::Delete() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::IMdmSession)->Delete());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Management_IMdmSession<D>::StartAsync() const
    {
        void* action{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::IMdmSession)->StartAsync(&action));
        return winrt::Windows::Foundation::IAsyncAction{ action, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Management_IMdmSession<D>::StartAsync(param::async_iterable<winrt::Windows::Management::MdmAlert> const& alerts) const
    {
        void* action{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::IMdmSession)->StartWithAlertsAsync(*(void**)(&alerts), &action));
        return winrt::Windows::Foundation::IAsyncAction{ action, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) consume_Windows_Management_IMdmSessionManagerStatics<D>::SessionIds() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::IMdmSessionManagerStatics)->get_SessionIds(&value));
        return winrt::Windows::Foundation::Collections::IVectorView<hstring>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Management::MdmSession) consume_Windows_Management_IMdmSessionManagerStatics<D>::TryCreateSession() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::IMdmSessionManagerStatics)->TryCreateSession(&result));
        return winrt::Windows::Management::MdmSession{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Management_IMdmSessionManagerStatics<D>::DeleteSessionById(param::hstring const& sessionId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::IMdmSessionManagerStatics)->DeleteSessionById(*(void**)(&sessionId)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Management::MdmSession) consume_Windows_Management_IMdmSessionManagerStatics<D>::GetSessionById(param::hstring const& sessionId) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Management::IMdmSessionManagerStatics)->GetSessionById(*(void**)(&sessionId), &result));
        return winrt::Windows::Management::MdmSession{ result, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Management::IMdmAlert> : produce_base<D, winrt::Windows::Management::IMdmAlert>
    {
        int32_t __stdcall get_Data(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Data());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Data(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Data(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Format(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Management::MdmAlertDataType>(this->shim().Format());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Format(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Format(*reinterpret_cast<winrt::Windows::Management::MdmAlertDataType const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Mark(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Management::MdmAlertMark>(this->shim().Mark());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Mark(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Mark(*reinterpret_cast<winrt::Windows::Management::MdmAlertMark const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Source(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Source());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Source(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Source(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Status(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Target(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Target());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Target(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Target(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Type(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Type(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Type(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Management::IMdmSession> : produce_base<D, winrt::Windows::Management::IMdmSession>
    {
        int32_t __stdcall get_Alerts(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Management::MdmAlert>>(this->shim().Alerts());
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
        int32_t __stdcall get_Id(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Id());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_State(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Management::MdmSessionState>(this->shim().State());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AttachAsync(void** action) noexcept final try
        {
            clear_abi(action);
            typename D::abi_guard guard(this->shim());
            *action = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().AttachAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Delete() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Delete();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartAsync(void** action) noexcept final try
        {
            clear_abi(action);
            typename D::abi_guard guard(this->shim());
            *action = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().StartAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall StartWithAlertsAsync(void* alerts, void** action) noexcept final try
        {
            clear_abi(action);
            typename D::abi_guard guard(this->shim());
            *action = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().StartAsync(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Management::MdmAlert> const*>(&alerts)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Management::IMdmSessionManagerStatics> : produce_base<D, winrt::Windows::Management::IMdmSessionManagerStatics>
    {
        int32_t __stdcall get_SessionIds(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::Collections::IVectorView<hstring>>(this->shim().SessionIds());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall TryCreateSession(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Management::MdmSession>(this->shim().TryCreateSession());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DeleteSessionById(void* sessionId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DeleteSessionById(*reinterpret_cast<hstring const*>(&sessionId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSessionById(void* sessionId, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Management::MdmSession>(this->shim().GetSessionById(*reinterpret_cast<hstring const*>(&sessionId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Management
{
    inline MdmAlert::MdmAlert() :
        MdmAlert(impl::call_factory_cast<MdmAlert(*)(winrt::Windows::Foundation::IActivationFactory const&), MdmAlert>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<MdmAlert>(); }))
    {
    }
    inline auto MdmSessionManager::SessionIds()
    {
        return impl::call_factory_cast<winrt::Windows::Foundation::Collections::IVectorView<hstring>(*)(IMdmSessionManagerStatics const&), MdmSessionManager, IMdmSessionManagerStatics>([](IMdmSessionManagerStatics const& f) { return f.SessionIds(); });
    }
    inline auto MdmSessionManager::TryCreateSession()
    {
        return impl::call_factory_cast<winrt::Windows::Management::MdmSession(*)(IMdmSessionManagerStatics const&), MdmSessionManager, IMdmSessionManagerStatics>([](IMdmSessionManagerStatics const& f) { return f.TryCreateSession(); });
    }
    inline auto MdmSessionManager::DeleteSessionById(param::hstring const& sessionId)
    {
        impl::call_factory<MdmSessionManager, IMdmSessionManagerStatics>([&](IMdmSessionManagerStatics const& f) { return f.DeleteSessionById(sessionId); });
    }
    inline auto MdmSessionManager::GetSessionById(param::hstring const& sessionId)
    {
        return impl::call_factory<MdmSessionManager, IMdmSessionManagerStatics>([&](IMdmSessionManagerStatics const& f) { return f.GetSessionById(sessionId); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Management::IMdmAlert> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Management::IMdmSession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Management::IMdmSessionManagerStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Management::MdmAlert> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Management::MdmSession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Management::MdmSessionManager> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
