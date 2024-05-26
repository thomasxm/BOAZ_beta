// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_ApplicationModel_Appointments_AppointmentsProvider_H
#define WINRT_Windows_ApplicationModel_Appointments_AppointmentsProvider_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.ApplicationModel.Appointments.h"
#include "winrt/impl/Windows.ApplicationModel.Appointments.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.ApplicationModel.Appointments.AppointmentsProvider.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Appointments::Appointment) consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IAddAppointmentOperation<D>::AppointmentInformation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IAddAppointmentOperation)->get_AppointmentInformation(&value));
        return winrt::Windows::ApplicationModel::Appointments::Appointment{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IAddAppointmentOperation<D>::SourcePackageFamilyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IAddAppointmentOperation)->get_SourcePackageFamilyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IAddAppointmentOperation<D>::ReportCompleted(param::hstring const& itemId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IAddAppointmentOperation)->ReportCompleted(*(void**)(&itemId)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IAddAppointmentOperation<D>::ReportCanceled() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IAddAppointmentOperation)->ReportCanceled());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IAddAppointmentOperation<D>::ReportError(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IAddAppointmentOperation)->ReportError(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IAddAppointmentOperation<D>::DismissUI() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IAddAppointmentOperation)->DismissUI());
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IAppointmentsProviderLaunchActionVerbsStatics<D>::AddAppointment() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IAppointmentsProviderLaunchActionVerbsStatics)->get_AddAppointment(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IAppointmentsProviderLaunchActionVerbsStatics<D>::ReplaceAppointment() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IAppointmentsProviderLaunchActionVerbsStatics)->get_ReplaceAppointment(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IAppointmentsProviderLaunchActionVerbsStatics<D>::RemoveAppointment() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IAppointmentsProviderLaunchActionVerbsStatics)->get_RemoveAppointment(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IAppointmentsProviderLaunchActionVerbsStatics<D>::ShowTimeFrame() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IAppointmentsProviderLaunchActionVerbsStatics)->get_ShowTimeFrame(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IAppointmentsProviderLaunchActionVerbsStatics2<D>::ShowAppointmentDetails() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IAppointmentsProviderLaunchActionVerbsStatics2)->get_ShowAppointmentDetails(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IRemoveAppointmentOperation<D>::AppointmentId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IRemoveAppointmentOperation)->get_AppointmentId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IRemoveAppointmentOperation<D>::InstanceStartDate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IRemoveAppointmentOperation)->get_InstanceStartDate(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IRemoveAppointmentOperation<D>::SourcePackageFamilyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IRemoveAppointmentOperation)->get_SourcePackageFamilyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IRemoveAppointmentOperation<D>::ReportCompleted() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IRemoveAppointmentOperation)->ReportCompleted());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IRemoveAppointmentOperation<D>::ReportCanceled() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IRemoveAppointmentOperation)->ReportCanceled());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IRemoveAppointmentOperation<D>::ReportError(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IRemoveAppointmentOperation)->ReportError(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IRemoveAppointmentOperation<D>::DismissUI() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IRemoveAppointmentOperation)->DismissUI());
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IReplaceAppointmentOperation<D>::AppointmentId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IReplaceAppointmentOperation)->get_AppointmentId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::Appointments::Appointment) consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IReplaceAppointmentOperation<D>::AppointmentInformation() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IReplaceAppointmentOperation)->get_AppointmentInformation(&value));
        return winrt::Windows::ApplicationModel::Appointments::Appointment{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IReplaceAppointmentOperation<D>::InstanceStartDate() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IReplaceAppointmentOperation)->get_InstanceStartDate(&value));
        return winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IReplaceAppointmentOperation<D>::SourcePackageFamilyName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IReplaceAppointmentOperation)->get_SourcePackageFamilyName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IReplaceAppointmentOperation<D>::ReportCompleted(param::hstring const& itemId) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IReplaceAppointmentOperation)->ReportCompleted(*(void**)(&itemId)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IReplaceAppointmentOperation<D>::ReportCanceled() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IReplaceAppointmentOperation)->ReportCanceled());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IReplaceAppointmentOperation<D>::ReportError(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IReplaceAppointmentOperation)->ReportError(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_ApplicationModel_Appointments_AppointmentsProvider_IReplaceAppointmentOperation<D>::DismissUI() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IReplaceAppointmentOperation)->DismissUI());
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IAddAppointmentOperation> : produce_base<D, winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IAddAppointmentOperation>
    {
        int32_t __stdcall get_AppointmentInformation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Appointments::Appointment>(this->shim().AppointmentInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SourcePackageFamilyName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SourcePackageFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportCompleted(void* itemId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportCompleted(*reinterpret_cast<hstring const*>(&itemId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportCanceled() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportCanceled();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportError(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportError(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DismissUI() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DismissUI();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IAppointmentsProviderLaunchActionVerbsStatics> : produce_base<D, winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IAppointmentsProviderLaunchActionVerbsStatics>
    {
        int32_t __stdcall get_AddAppointment(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AddAppointment());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ReplaceAppointment(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ReplaceAppointment());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RemoveAppointment(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().RemoveAppointment());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ShowTimeFrame(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ShowTimeFrame());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IAppointmentsProviderLaunchActionVerbsStatics2> : produce_base<D, winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IAppointmentsProviderLaunchActionVerbsStatics2>
    {
        int32_t __stdcall get_ShowAppointmentDetails(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ShowAppointmentDetails());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IRemoveAppointmentOperation> : produce_base<D, winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IRemoveAppointmentOperation>
    {
        int32_t __stdcall get_AppointmentId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AppointmentId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InstanceStartDate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().InstanceStartDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SourcePackageFamilyName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SourcePackageFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportCompleted() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportCompleted();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportCanceled() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportCanceled();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportError(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportError(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DismissUI() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DismissUI();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IReplaceAppointmentOperation> : produce_base<D, winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IReplaceAppointmentOperation>
    {
        int32_t __stdcall get_AppointmentId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().AppointmentId());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AppointmentInformation(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::Appointments::Appointment>(this->shim().AppointmentInformation());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_InstanceStartDate(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>>(this->shim().InstanceStartDate());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SourcePackageFamilyName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().SourcePackageFamilyName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportCompleted(void* itemId) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportCompleted(*reinterpret_cast<hstring const*>(&itemId));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportCanceled() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportCanceled();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ReportError(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ReportError(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall DismissUI() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().DismissUI();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider
{
    inline auto AppointmentsProviderLaunchActionVerbs::AddAppointment()
    {
        return impl::call_factory_cast<hstring(*)(IAppointmentsProviderLaunchActionVerbsStatics const&), AppointmentsProviderLaunchActionVerbs, IAppointmentsProviderLaunchActionVerbsStatics>([](IAppointmentsProviderLaunchActionVerbsStatics const& f) { return f.AddAppointment(); });
    }
    inline auto AppointmentsProviderLaunchActionVerbs::ReplaceAppointment()
    {
        return impl::call_factory_cast<hstring(*)(IAppointmentsProviderLaunchActionVerbsStatics const&), AppointmentsProviderLaunchActionVerbs, IAppointmentsProviderLaunchActionVerbsStatics>([](IAppointmentsProviderLaunchActionVerbsStatics const& f) { return f.ReplaceAppointment(); });
    }
    inline auto AppointmentsProviderLaunchActionVerbs::RemoveAppointment()
    {
        return impl::call_factory_cast<hstring(*)(IAppointmentsProviderLaunchActionVerbsStatics const&), AppointmentsProviderLaunchActionVerbs, IAppointmentsProviderLaunchActionVerbsStatics>([](IAppointmentsProviderLaunchActionVerbsStatics const& f) { return f.RemoveAppointment(); });
    }
    inline auto AppointmentsProviderLaunchActionVerbs::ShowTimeFrame()
    {
        return impl::call_factory_cast<hstring(*)(IAppointmentsProviderLaunchActionVerbsStatics const&), AppointmentsProviderLaunchActionVerbs, IAppointmentsProviderLaunchActionVerbsStatics>([](IAppointmentsProviderLaunchActionVerbsStatics const& f) { return f.ShowTimeFrame(); });
    }
    inline auto AppointmentsProviderLaunchActionVerbs::ShowAppointmentDetails()
    {
        return impl::call_factory_cast<hstring(*)(IAppointmentsProviderLaunchActionVerbsStatics2 const&), AppointmentsProviderLaunchActionVerbs, IAppointmentsProviderLaunchActionVerbsStatics2>([](IAppointmentsProviderLaunchActionVerbsStatics2 const& f) { return f.ShowAppointmentDetails(); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IAddAppointmentOperation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IAppointmentsProviderLaunchActionVerbsStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IAppointmentsProviderLaunchActionVerbsStatics2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IRemoveAppointmentOperation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::IReplaceAppointmentOperation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::AddAppointmentOperation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::AppointmentsProviderLaunchActionVerbs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::RemoveAppointmentOperation> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::ApplicationModel::Appointments::AppointmentsProvider::ReplaceAppointmentOperation> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
