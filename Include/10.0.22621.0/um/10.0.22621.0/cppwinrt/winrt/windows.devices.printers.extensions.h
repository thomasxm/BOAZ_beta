// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Printers_Extensions_H
#define WINRT_Windows_Devices_Printers_Extensions_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Devices.Printers.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Devices.Printers.Extensions.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflow<D>::DeviceID() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflow)->get_DeviceID(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflow<D>::GetPrintModelPackage() const
    {
        void* printModelPackage{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflow)->GetPrintModelPackage(&printModelPackage));
        return winrt::Windows::Foundation::IInspectable{ printModelPackage, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflow<D>::IsPrintReady() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflow)->get_IsPrintReady(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflow<D>::IsPrintReady(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflow)->put_IsPrintReady(value));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflow<D>::PrintRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Printers::Extensions::Print3DWorkflow, winrt::Windows::Devices::Printers::Extensions::Print3DWorkflowPrintRequestedEventArgs> const& eventHandler) const
    {
        winrt::event_token eventCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflow)->add_PrintRequested(*(void**)(&eventHandler), put_abi(eventCookie)));
        return eventCookie;
    }
    template <typename D> typename consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflow<D>::PrintRequested_revoker consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflow<D>::PrintRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Printers::Extensions::Print3DWorkflow, winrt::Windows::Devices::Printers::Extensions::Print3DWorkflowPrintRequestedEventArgs> const& eventHandler) const
    {
        return impl::make_event_revoker<D, PrintRequested_revoker>(this, PrintRequested(eventHandler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflow<D>::PrintRequested(winrt::event_token const& eventCookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflow)->remove_PrintRequested(impl::bind_in(eventCookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflow2<D>::PrinterChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Printers::Extensions::Print3DWorkflow, winrt::Windows::Devices::Printers::Extensions::Print3DWorkflowPrinterChangedEventArgs> const& eventHandler) const
    {
        winrt::event_token eventCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflow2)->add_PrinterChanged(*(void**)(&eventHandler), put_abi(eventCookie)));
        return eventCookie;
    }
    template <typename D> typename consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflow2<D>::PrinterChanged_revoker consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflow2<D>::PrinterChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Printers::Extensions::Print3DWorkflow, winrt::Windows::Devices::Printers::Extensions::Print3DWorkflowPrinterChangedEventArgs> const& eventHandler) const
    {
        return impl::make_event_revoker<D, PrinterChanged_revoker>(this, PrinterChanged(eventHandler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflow2<D>::PrinterChanged(winrt::event_token const& eventCookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflow2)->remove_PrinterChanged(impl::bind_in(eventCookie));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::Extensions::Print3DWorkflowStatus) consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflowPrintRequestedEventArgs<D>::Status() const
    {
        winrt::Windows::Devices::Printers::Extensions::Print3DWorkflowStatus value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflowPrintRequestedEventArgs)->get_Status(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflowPrintRequestedEventArgs<D>::SetExtendedStatus(winrt::Windows::Devices::Printers::Extensions::Print3DWorkflowDetail const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflowPrintRequestedEventArgs)->SetExtendedStatus(static_cast<int32_t>(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflowPrintRequestedEventArgs<D>::SetSource(winrt::Windows::Foundation::IInspectable const& source) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflowPrintRequestedEventArgs)->SetSource(*(void**)(&source)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflowPrintRequestedEventArgs<D>::SetSourceChanged(bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflowPrintRequestedEventArgs)->SetSourceChanged(value));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Printers_Extensions_IPrint3DWorkflowPrinterChangedEventArgs<D>::NewDeviceId() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflowPrinterChangedEventArgs)->get_NewDeviceId(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_Devices_Printers_Extensions_IPrintExtensionContextStatic<D>::FromDeviceId(param::hstring const& deviceId) const
    {
        void* context{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::Extensions::IPrintExtensionContextStatic)->FromDeviceId(*(void**)(&deviceId), &context));
        return winrt::Windows::Foundation::IInspectable{ context, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Printers_Extensions_IPrintNotificationEventDetails<D>::PrinterName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::Extensions::IPrintNotificationEventDetails)->get_PrinterName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Devices_Printers_Extensions_IPrintNotificationEventDetails<D>::EventData() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::Extensions::IPrintNotificationEventDetails)->get_EventData(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Printers_Extensions_IPrintNotificationEventDetails<D>::EventData(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::Extensions::IPrintNotificationEventDetails)->put_EventData(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_Devices_Printers_Extensions_IPrintTaskConfiguration<D>::PrinterExtensionContext() const
    {
        void* context{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfiguration)->get_PrinterExtensionContext(&context));
        return winrt::Windows::Foundation::IInspectable{ context, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Devices_Printers_Extensions_IPrintTaskConfiguration<D>::SaveRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Printers::Extensions::PrintTaskConfiguration, winrt::Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequestedEventArgs> const& eventHandler) const
    {
        winrt::event_token eventCookie{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfiguration)->add_SaveRequested(*(void**)(&eventHandler), put_abi(eventCookie)));
        return eventCookie;
    }
    template <typename D> typename consume_Windows_Devices_Printers_Extensions_IPrintTaskConfiguration<D>::SaveRequested_revoker consume_Windows_Devices_Printers_Extensions_IPrintTaskConfiguration<D>::SaveRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Printers::Extensions::PrintTaskConfiguration, winrt::Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequestedEventArgs> const& eventHandler) const
    {
        return impl::make_event_revoker<D, SaveRequested_revoker>(this, SaveRequested(eventHandler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Printers_Extensions_IPrintTaskConfiguration<D>::SaveRequested(winrt::event_token const& eventCookie) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfiguration)->remove_SaveRequested(impl::bind_in(eventCookie));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Printers_Extensions_IPrintTaskConfigurationSaveRequest<D>::Cancel() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequest)->Cancel());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Printers_Extensions_IPrintTaskConfigurationSaveRequest<D>::Save(winrt::Windows::Foundation::IInspectable const& printerExtensionContext) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequest)->Save(*(void**)(&printerExtensionContext)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequestedDeferral) consume_Windows_Devices_Printers_Extensions_IPrintTaskConfigurationSaveRequest<D>::GetDeferral() const
    {
        void* deferral{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequest)->GetDeferral(&deferral));
        return winrt::Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequestedDeferral{ deferral, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) consume_Windows_Devices_Printers_Extensions_IPrintTaskConfigurationSaveRequest<D>::Deadline() const
    {
        winrt::Windows::Foundation::DateTime value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequest)->get_Deadline(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Devices_Printers_Extensions_IPrintTaskConfigurationSaveRequestedDeferral<D>::Complete() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequestedDeferral)->Complete());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequest) consume_Windows_Devices_Printers_Extensions_IPrintTaskConfigurationSaveRequestedEventArgs<D>::Request() const
    {
        void* context{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequestedEventArgs)->get_Request(&context));
        return winrt::Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequest{ context, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflow> : produce_base<D, winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflow>
    {
        int32_t __stdcall get_DeviceID(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DeviceID());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPrintModelPackage(void** printModelPackage) noexcept final try
        {
            clear_abi(printModelPackage);
            typename D::abi_guard guard(this->shim());
            *printModelPackage = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().GetPrintModelPackage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsPrintReady(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsPrintReady());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_IsPrintReady(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().IsPrintReady(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_PrintRequested(void* eventHandler, winrt::event_token* eventCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(eventCookie);
            typename D::abi_guard guard(this->shim());
            *eventCookie = detach_from<winrt::event_token>(this->shim().PrintRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Printers::Extensions::Print3DWorkflow, winrt::Windows::Devices::Printers::Extensions::Print3DWorkflowPrintRequestedEventArgs> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PrintRequested(winrt::event_token eventCookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PrintRequested(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflow2> : produce_base<D, winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflow2>
    {
        int32_t __stdcall add_PrinterChanged(void* eventHandler, winrt::event_token* eventCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(eventCookie);
            typename D::abi_guard guard(this->shim());
            *eventCookie = detach_from<winrt::event_token>(this->shim().PrinterChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Printers::Extensions::Print3DWorkflow, winrt::Windows::Devices::Printers::Extensions::Print3DWorkflowPrinterChangedEventArgs> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PrinterChanged(winrt::event_token eventCookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PrinterChanged(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflowPrintRequestedEventArgs> : produce_base<D, winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflowPrintRequestedEventArgs>
    {
        int32_t __stdcall get_Status(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Printers::Extensions::Print3DWorkflowStatus>(this->shim().Status());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetExtendedStatus(int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetExtendedStatus(*reinterpret_cast<winrt::Windows::Devices::Printers::Extensions::Print3DWorkflowDetail const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetSource(void* source) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetSource(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&source));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetSourceChanged(bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetSourceChanged(value);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflowPrinterChangedEventArgs> : produce_base<D, winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflowPrinterChangedEventArgs>
    {
        int32_t __stdcall get_NewDeviceId(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().NewDeviceId());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Printers::Extensions::IPrintExtensionContextStatic> : produce_base<D, winrt::Windows::Devices::Printers::Extensions::IPrintExtensionContextStatic>
    {
        int32_t __stdcall FromDeviceId(void* deviceId, void** context) noexcept final try
        {
            clear_abi(context);
            typename D::abi_guard guard(this->shim());
            *context = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().FromDeviceId(*reinterpret_cast<hstring const*>(&deviceId)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Printers::Extensions::IPrintNotificationEventDetails> : produce_base<D, winrt::Windows::Devices::Printers::Extensions::IPrintNotificationEventDetails>
    {
        int32_t __stdcall get_PrinterName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().PrinterName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_EventData(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().EventData());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_EventData(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().EventData(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfiguration> : produce_base<D, winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfiguration>
    {
        int32_t __stdcall get_PrinterExtensionContext(void** context) noexcept final try
        {
            clear_abi(context);
            typename D::abi_guard guard(this->shim());
            *context = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().PrinterExtensionContext());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_SaveRequested(void* eventHandler, winrt::event_token* eventCookie) noexcept final try
        {
            zero_abi<winrt::event_token>(eventCookie);
            typename D::abi_guard guard(this->shim());
            *eventCookie = detach_from<winrt::event_token>(this->shim().SaveRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Printers::Extensions::PrintTaskConfiguration, winrt::Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequestedEventArgs> const*>(&eventHandler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_SaveRequested(winrt::event_token eventCookie) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SaveRequested(*reinterpret_cast<winrt::event_token const*>(&eventCookie));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequest> : produce_base<D, winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequest>
    {
        int32_t __stdcall Cancel() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Cancel();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall Save(void* printerExtensionContext) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Save(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&printerExtensionContext));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** deferral) noexcept final try
        {
            clear_abi(deferral);
            typename D::abi_guard guard(this->shim());
            *deferral = detach_from<winrt::Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequestedDeferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Deadline(int64_t* value) noexcept final try
        {
            zero_abi<winrt::Windows::Foundation::DateTime>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Foundation::DateTime>(this->shim().Deadline());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequestedDeferral> : produce_base<D, winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequestedDeferral>
    {
        int32_t __stdcall Complete() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Complete();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequestedEventArgs> : produce_base<D, winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequestedEventArgs>
    {
        int32_t __stdcall get_Request(void** context) noexcept final try
        {
            clear_abi(context);
            typename D::abi_guard guard(this->shim());
            *context = detach_from<winrt::Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequest>(this->shim().Request());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Devices::Printers::Extensions
{
    inline auto PrintExtensionContext::FromDeviceId(param::hstring const& deviceId)
    {
        return impl::call_factory<PrintExtensionContext, IPrintExtensionContextStatic>([&](IPrintExtensionContextStatic const& f) { return f.FromDeviceId(deviceId); });
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflow> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflow2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflowPrintRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::Extensions::IPrint3DWorkflowPrinterChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::Extensions::IPrintExtensionContextStatic> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::Extensions::IPrintNotificationEventDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequestedDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::Extensions::IPrintTaskConfigurationSaveRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::Extensions::Print3DWorkflow> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::Extensions::Print3DWorkflowPrintRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::Extensions::Print3DWorkflowPrinterChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::Extensions::PrintExtensionContext> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::Extensions::PrintNotificationEventDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::Extensions::PrintTaskConfiguration> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequest> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequestedDeferral> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Devices::Printers::Extensions::PrintTaskConfigurationSaveRequestedEventArgs> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
