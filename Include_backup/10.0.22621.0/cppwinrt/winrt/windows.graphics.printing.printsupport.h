// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Graphics_Printing_PrintSupport_H
#define WINRT_Windows_Graphics_Printing_PrintSupport_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Graphics.Printing.h"
#include "winrt/impl/Windows.ApplicationModel.2.h"
#include "winrt/impl/Windows.ApplicationModel.Activation.2.h"
#include "winrt/impl/Windows.Data.Xml.Dom.2.h"
#include "winrt/impl/Windows.Devices.Printers.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Graphics.Printing.PrintTicket.2.h"
#include "winrt/impl/Windows.UI.Shell.2.h"
#include "winrt/impl/Windows.Graphics.Printing.PrintSupport.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppPrintDevice) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportExtensionSession<D>::Printer() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportExtensionSession)->get_Printer(&value));
        return winrt::Windows::Devices::Printers::IppPrintDevice{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportExtensionSession<D>::PrintTicketValidationRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportExtensionSession, winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportPrintTicketValidationRequestedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportExtensionSession)->add_PrintTicketValidationRequested(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportExtensionSession<D>::PrintTicketValidationRequested_revoker consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportExtensionSession<D>::PrintTicketValidationRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportExtensionSession, winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportPrintTicketValidationRequestedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PrintTicketValidationRequested_revoker>(this, PrintTicketValidationRequested(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportExtensionSession<D>::PrintTicketValidationRequested(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportExtensionSession)->remove_PrintTicketValidationRequested(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportExtensionSession<D>::PrintDeviceCapabilitiesChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportExtensionSession, winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportPrintDeviceCapabilitiesChangedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportExtensionSession)->add_PrintDeviceCapabilitiesChanged(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportExtensionSession<D>::PrintDeviceCapabilitiesChanged_revoker consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportExtensionSession<D>::PrintDeviceCapabilitiesChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportExtensionSession, winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportPrintDeviceCapabilitiesChangedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PrintDeviceCapabilitiesChanged_revoker>(this, PrintDeviceCapabilitiesChanged(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportExtensionSession<D>::PrintDeviceCapabilitiesChanged(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportExtensionSession)->remove_PrintDeviceCapabilitiesChanged(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportExtensionSession<D>::Start() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportExtensionSession)->Start());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::event_token) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportExtensionSession2<D>::PrinterSelected(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportExtensionSession, winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportPrinterSelectedEventArgs> const& handler) const
    {
        winrt::event_token token{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportExtensionSession2)->add_PrinterSelected(*(void**)(&handler), put_abi(token)));
        return token;
    }
    template <typename D> typename consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportExtensionSession2<D>::PrinterSelected_revoker consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportExtensionSession2<D>::PrinterSelected(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportExtensionSession, winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportPrinterSelectedEventArgs> const& handler) const
    {
        return impl::make_event_revoker<D, PrinterSelected_revoker>(this, PrinterSelected(handler));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportExtensionSession2<D>::PrinterSelected(winrt::event_token const& token) const noexcept
    {
        WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportExtensionSession2)->remove_PrinterSelected(impl::bind_in(token));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportExtensionSession) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportExtensionTriggerDetails<D>::Session() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportExtensionTriggerDetails)->get_Session(&value));
        return winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportExtensionSession{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlDocument) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportPrintDeviceCapabilitiesChangedEventArgs<D>::GetCurrentPrintDeviceCapabilities() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintDeviceCapabilitiesChangedEventArgs)->GetCurrentPrintDeviceCapabilities(&result));
        return winrt::Windows::Data::Xml::Dom::XmlDocument{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportPrintDeviceCapabilitiesChangedEventArgs<D>::UpdatePrintDeviceCapabilities(winrt::Windows::Data::Xml::Dom::XmlDocument const& updatedPdc) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintDeviceCapabilitiesChangedEventArgs)->UpdatePrintDeviceCapabilities(*(void**)(&updatedPdc)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportPrintDeviceCapabilitiesChangedEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintDeviceCapabilitiesChangedEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportPrintDeviceCapabilitiesChangedEventArgs2<D>::SetSupportedPdlPassthroughContentTypes(param::iterable<hstring> const& supportedPdlContentTypes) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintDeviceCapabilitiesChangedEventArgs2)->SetSupportedPdlPassthroughContentTypes(*(void**)(&supportedPdlContentTypes)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportPrintDeviceCapabilitiesChangedEventArgs2<D>::ResourceLanguage() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintDeviceCapabilitiesChangedEventArgs2)->get_ResourceLanguage(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlDocument) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportPrintDeviceCapabilitiesChangedEventArgs2<D>::GetCurrentPrintDeviceResources() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintDeviceCapabilitiesChangedEventArgs2)->GetCurrentPrintDeviceResources(&result));
        return winrt::Windows::Data::Xml::Dom::XmlDocument{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportPrintDeviceCapabilitiesChangedEventArgs2<D>::UpdatePrintDeviceResources(winrt::Windows::Data::Xml::Dom::XmlDocument const& updatedPdr) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintDeviceCapabilitiesChangedEventArgs2)->UpdatePrintDeviceResources(*(void**)(&updatedPdr)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportPrintDeviceCapabilitiesChangedEventArgs2<D>::SetPrintDeviceCapabilitiesUpdatePolicy(winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportPrintDeviceCapabilitiesUpdatePolicy const& updatePolicy) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintDeviceCapabilitiesChangedEventArgs2)->SetPrintDeviceCapabilitiesUpdatePolicy(*(void**)(&updatePolicy)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportPrintDeviceCapabilitiesUpdatePolicy) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportPrintDeviceCapabilitiesUpdatePolicyStatics<D>::CreatePeriodicRefresh(winrt::Windows::Foundation::TimeSpan const& updatePeriod) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintDeviceCapabilitiesUpdatePolicyStatics)->CreatePeriodicRefresh(impl::bind_in(updatePeriod), &result));
        return winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportPrintDeviceCapabilitiesUpdatePolicy{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportPrintDeviceCapabilitiesUpdatePolicy) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportPrintDeviceCapabilitiesUpdatePolicyStatics<D>::CreatePrintJobRefresh(uint32_t numberOfJobs) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintDeviceCapabilitiesUpdatePolicyStatics)->CreatePrintJobRefresh(numberOfJobs, &result));
        return winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportPrintDeviceCapabilitiesUpdatePolicy{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportPrintTicketElement<D>::LocalName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintTicketElement)->get_LocalName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportPrintTicketElement<D>::LocalName(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintTicketElement)->put_LocalName(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportPrintTicketElement<D>::NamespaceUri() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintTicketElement)->get_NamespaceUri(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportPrintTicketElement<D>::NamespaceUri(param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintTicketElement)->put_NamespaceUri(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportPrintTicketValidationRequestedEventArgs<D>::PrintTicket() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintTicketValidationRequestedEventArgs)->get_PrintTicket(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportPrintTicketValidationRequestedEventArgs<D>::SetPrintTicketValidationStatus(winrt::Windows::Graphics::Printing::PrintSupport::WorkflowPrintTicketValidationStatus const& status) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintTicketValidationRequestedEventArgs)->SetPrintTicketValidationStatus(static_cast<int32_t>(status)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportPrintTicketValidationRequestedEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintTicketValidationRequestedEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::AppInfo) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportPrinterSelectedEventArgs<D>::SourceAppInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrinterSelectedEventArgs)->get_SourceAppInfo(&value));
        return winrt::Windows::ApplicationModel::AppInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportPrinterSelectedEventArgs<D>::PrintTicket() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrinterSelectedEventArgs)->get_PrintTicket(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportPrinterSelectedEventArgs<D>::PrintTicket(winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrinterSelectedEventArgs)->put_PrintTicket(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportPrinterSelectedEventArgs<D>::SetAdditionalFeatures(param::iterable<winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportPrintTicketElement> const& features) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrinterSelectedEventArgs)->SetAdditionalFeatures(*(void**)(&features)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportPrinterSelectedEventArgs<D>::SetAdditionalParameters(param::iterable<winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportPrintTicketElement> const& parameters) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrinterSelectedEventArgs)->SetAdditionalParameters(*(void**)(&parameters)));
    }
    template <typename D> WINRT_IMPL_AUTO(uint32_t) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportPrinterSelectedEventArgs<D>::AllowedAdditionalFeaturesAndParametersCount() const
    {
        uint32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrinterSelectedEventArgs)->get_AllowedAdditionalFeaturesAndParametersCount(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportPrinterSelectedEventArgs<D>::SetAdaptiveCard(winrt::Windows::UI::Shell::IAdaptiveCard const& adaptiveCard) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrinterSelectedEventArgs)->SetAdaptiveCard(*(void**)(&adaptiveCard)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportPrinterSelectedEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrinterSelectedEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::ApplicationModel::AppInfo) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportSessionInfo<D>::SourceAppInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportSessionInfo)->get_SourceAppInfo(&value));
        return winrt::Windows::ApplicationModel::AppInfo{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Devices::Printers::IppPrintDevice) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportSessionInfo<D>::Printer() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportSessionInfo)->get_Printer(&value));
        return winrt::Windows::Devices::Printers::IppPrintDevice{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportSettingsUISession) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportSettingsActivatedEventArgs<D>::Session() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportSettingsActivatedEventArgs)->get_Session(&value));
        return winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportSettingsUISession{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Deferral) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportSettingsActivatedEventArgs<D>::GetDeferral() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportSettingsActivatedEventArgs)->GetDeferral(&result));
        return winrt::Windows::Foundation::Deferral{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportSettingsUISession<D>::SessionPrintTicket() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportSettingsUISession)->get_SessionPrintTicket(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportSettingsUISession<D>::DocumentTitle() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportSettingsUISession)->get_DocumentTitle(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintSupport::SettingsLaunchKind) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportSettingsUISession<D>::LaunchKind() const
    {
        winrt::Windows::Graphics::Printing::PrintSupport::SettingsLaunchKind value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportSettingsUISession)->get_LaunchKind(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportSettingsUISession<D>::UpdatePrintTicket(winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket const& printTicket) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportSettingsUISession)->UpdatePrintTicket(*(void**)(&printTicket)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportSessionInfo) consume_Windows_Graphics_Printing_PrintSupport_IPrintSupportSettingsUISession<D>::SessionInfo() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportSettingsUISession)->get_SessionInfo(&value));
        return winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportSessionInfo{ value, take_ownership_from_abi };
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportExtensionSession> : produce_base<D, winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportExtensionSession>
    {
        int32_t __stdcall get_Printer(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Printers::IppPrintDevice>(this->shim().Printer());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall add_PrintTicketValidationRequested(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PrintTicketValidationRequested(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportExtensionSession, winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportPrintTicketValidationRequestedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PrintTicketValidationRequested(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PrintTicketValidationRequested(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall add_PrintDeviceCapabilitiesChanged(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PrintDeviceCapabilitiesChanged(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportExtensionSession, winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportPrintDeviceCapabilitiesChangedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PrintDeviceCapabilitiesChanged(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PrintDeviceCapabilitiesChanged(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
        int32_t __stdcall Start() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Start();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportExtensionSession2> : produce_base<D, winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportExtensionSession2>
    {
        int32_t __stdcall add_PrinterSelected(void* handler, winrt::event_token* token) noexcept final try
        {
            zero_abi<winrt::event_token>(token);
            typename D::abi_guard guard(this->shim());
            *token = detach_from<winrt::event_token>(this->shim().PrinterSelected(*reinterpret_cast<winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportExtensionSession, winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportPrinterSelectedEventArgs> const*>(&handler)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall remove_PrinterSelected(winrt::event_token token) noexcept final
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PrinterSelected(*reinterpret_cast<winrt::event_token const*>(&token));
            return 0;
        }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportExtensionTriggerDetails> : produce_base<D, winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportExtensionTriggerDetails>
    {
        int32_t __stdcall get_Session(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportExtensionSession>(this->shim().Session());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintDeviceCapabilitiesChangedEventArgs> : produce_base<D, winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintDeviceCapabilitiesChangedEventArgs>
    {
        int32_t __stdcall GetCurrentPrintDeviceCapabilities(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Data::Xml::Dom::XmlDocument>(this->shim().GetCurrentPrintDeviceCapabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpdatePrintDeviceCapabilities(void* updatedPdc) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UpdatePrintDeviceCapabilities(*reinterpret_cast<winrt::Windows::Data::Xml::Dom::XmlDocument const*>(&updatedPdc));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintDeviceCapabilitiesChangedEventArgs2> : produce_base<D, winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintDeviceCapabilitiesChangedEventArgs2>
    {
        int32_t __stdcall SetSupportedPdlPassthroughContentTypes(void* supportedPdlContentTypes) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetSupportedPdlPassthroughContentTypes(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<hstring> const*>(&supportedPdlContentTypes));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ResourceLanguage(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().ResourceLanguage());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCurrentPrintDeviceResources(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Data::Xml::Dom::XmlDocument>(this->shim().GetCurrentPrintDeviceResources());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpdatePrintDeviceResources(void* updatedPdr) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UpdatePrintDeviceResources(*reinterpret_cast<winrt::Windows::Data::Xml::Dom::XmlDocument const*>(&updatedPdr));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPrintDeviceCapabilitiesUpdatePolicy(void* updatePolicy) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPrintDeviceCapabilitiesUpdatePolicy(*reinterpret_cast<winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportPrintDeviceCapabilitiesUpdatePolicy const*>(&updatePolicy));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintDeviceCapabilitiesUpdatePolicy> : produce_base<D, winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintDeviceCapabilitiesUpdatePolicy>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintDeviceCapabilitiesUpdatePolicyStatics> : produce_base<D, winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintDeviceCapabilitiesUpdatePolicyStatics>
    {
        int32_t __stdcall CreatePeriodicRefresh(int64_t updatePeriod, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportPrintDeviceCapabilitiesUpdatePolicy>(this->shim().CreatePeriodicRefresh(*reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&updatePeriod)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreatePrintJobRefresh(uint32_t numberOfJobs, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportPrintDeviceCapabilitiesUpdatePolicy>(this->shim().CreatePrintJobRefresh(numberOfJobs));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintTicketElement> : produce_base<D, winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintTicketElement>
    {
        int32_t __stdcall get_LocalName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().LocalName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_LocalName(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().LocalName(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_NamespaceUri(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().NamespaceUri());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_NamespaceUri(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().NamespaceUri(*reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintTicketValidationRequestedEventArgs> : produce_base<D, winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintTicketValidationRequestedEventArgs>
    {
        int32_t __stdcall get_PrintTicket(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket>(this->shim().PrintTicket());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPrintTicketValidationStatus(int32_t status) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPrintTicketValidationStatus(*reinterpret_cast<winrt::Windows::Graphics::Printing::PrintSupport::WorkflowPrintTicketValidationStatus const*>(&status));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrinterSelectedEventArgs> : produce_base<D, winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrinterSelectedEventArgs>
    {
        int32_t __stdcall get_SourceAppInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::AppInfo>(this->shim().SourceAppInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PrintTicket(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket>(this->shim().PrintTicket());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_PrintTicket(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().PrintTicket(*reinterpret_cast<winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetAdditionalFeatures(void* features) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetAdditionalFeatures(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportPrintTicketElement> const*>(&features));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetAdditionalParameters(void* parameters) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetAdditionalParameters(*reinterpret_cast<winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportPrintTicketElement> const*>(&parameters));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_AllowedAdditionalFeaturesAndParametersCount(uint32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<uint32_t>(this->shim().AllowedAdditionalFeaturesAndParametersCount());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetAdaptiveCard(void* adaptiveCard) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetAdaptiveCard(*reinterpret_cast<winrt::Windows::UI::Shell::IAdaptiveCard const*>(&adaptiveCard));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportSessionInfo> : produce_base<D, winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportSessionInfo>
    {
        int32_t __stdcall get_SourceAppInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::ApplicationModel::AppInfo>(this->shim().SourceAppInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Printer(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Devices::Printers::IppPrintDevice>(this->shim().Printer());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportSettingsActivatedEventArgs> : produce_base<D, winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportSettingsActivatedEventArgs>
    {
        int32_t __stdcall get_Session(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportSettingsUISession>(this->shim().Session());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDeferral(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Deferral>(this->shim().GetDeferral());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportSettingsUISession> : produce_base<D, winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportSettingsUISession>
    {
        int32_t __stdcall get_SessionPrintTicket(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket>(this->shim().SessionPrintTicket());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DocumentTitle(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DocumentTitle());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_LaunchKind(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintSupport::SettingsLaunchKind>(this->shim().LaunchKind());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall UpdatePrintTicket(void* printTicket) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UpdatePrintTicket(*reinterpret_cast<winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket const*>(&printTicket));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SessionInfo(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportSessionInfo>(this->shim().SessionInfo());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Graphics::Printing::PrintSupport
{
    inline auto PrintSupportPrintDeviceCapabilitiesUpdatePolicy::CreatePeriodicRefresh(winrt::Windows::Foundation::TimeSpan const& updatePeriod)
    {
        return impl::call_factory<PrintSupportPrintDeviceCapabilitiesUpdatePolicy, IPrintSupportPrintDeviceCapabilitiesUpdatePolicyStatics>([&](IPrintSupportPrintDeviceCapabilitiesUpdatePolicyStatics const& f) { return f.CreatePeriodicRefresh(updatePeriod); });
    }
    inline auto PrintSupportPrintDeviceCapabilitiesUpdatePolicy::CreatePrintJobRefresh(uint32_t numberOfJobs)
    {
        return impl::call_factory<PrintSupportPrintDeviceCapabilitiesUpdatePolicy, IPrintSupportPrintDeviceCapabilitiesUpdatePolicyStatics>([&](IPrintSupportPrintDeviceCapabilitiesUpdatePolicyStatics const& f) { return f.CreatePrintJobRefresh(numberOfJobs); });
    }
    inline PrintSupportPrintTicketElement::PrintSupportPrintTicketElement() :
        PrintSupportPrintTicketElement(impl::call_factory_cast<PrintSupportPrintTicketElement(*)(winrt::Windows::Foundation::IActivationFactory const&), PrintSupportPrintTicketElement>([](winrt::Windows::Foundation::IActivationFactory const& f) { return f.template ActivateInstance<PrintSupportPrintTicketElement>(); }))
    {
    }
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportExtensionSession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportExtensionSession2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportExtensionTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintDeviceCapabilitiesChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintDeviceCapabilitiesChangedEventArgs2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintDeviceCapabilitiesUpdatePolicy> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintDeviceCapabilitiesUpdatePolicyStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintTicketElement> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrintTicketValidationRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportPrinterSelectedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportSessionInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportSettingsActivatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintSupport::IPrintSupportSettingsUISession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportExtensionSession> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportExtensionTriggerDetails> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportPrintDeviceCapabilitiesChangedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportPrintDeviceCapabilitiesUpdatePolicy> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportPrintTicketElement> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportPrintTicketValidationRequestedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportPrinterSelectedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportSessionInfo> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportSettingsActivatedEventArgs> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintSupport::PrintSupportSettingsUISession> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
