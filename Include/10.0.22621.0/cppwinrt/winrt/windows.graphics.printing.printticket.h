// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Graphics_Printing_PrintTicket_H
#define WINRT_Windows_Graphics_Printing_PrintTicket_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.Graphics.Printing.h"
#include "winrt/impl/Windows.Data.Xml.Dom.2.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Graphics.Printing.PrintTicket.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketCapabilities<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketCapabilities<D>::XmlNamespace() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities)->get_XmlNamespace(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlNode) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketCapabilities<D>::XmlNode() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities)->get_XmlNode(&value));
        return winrt::Windows::Data::Xml::Dom::IXmlNode{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketCapabilities<D>::DocumentBindingFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities)->get_DocumentBindingFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketCapabilities<D>::DocumentCollateFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities)->get_DocumentCollateFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketCapabilities<D>::DocumentDuplexFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities)->get_DocumentDuplexFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketCapabilities<D>::DocumentHolePunchFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities)->get_DocumentHolePunchFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketCapabilities<D>::DocumentInputBinFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities)->get_DocumentInputBinFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketCapabilities<D>::DocumentNUpFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities)->get_DocumentNUpFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketCapabilities<D>::DocumentStapleFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities)->get_DocumentStapleFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketCapabilities<D>::JobPasscodeFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities)->get_JobPasscodeFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketCapabilities<D>::PageBorderlessFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities)->get_PageBorderlessFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketCapabilities<D>::PageMediaSizeFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities)->get_PageMediaSizeFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketCapabilities<D>::PageMediaTypeFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities)->get_PageMediaTypeFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketCapabilities<D>::PageOrientationFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities)->get_PageOrientationFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketCapabilities<D>::PageOutputColorFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities)->get_PageOutputColorFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketCapabilities<D>::PageOutputQualityFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities)->get_PageOutputQualityFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketCapabilities<D>::PageResolutionFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities)->get_PageResolutionFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketCapabilities<D>::GetFeature(param::hstring const& name, param::hstring const& xmlNamespace) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities)->GetFeature(*(void**)(&name), *(void**)(&xmlNamespace), &result));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketParameterDefinition) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketCapabilities<D>::GetParameterDefinition(param::hstring const& name, param::hstring const& xmlNamespace) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities)->GetParameterDefinition(*(void**)(&name), *(void**)(&xmlNamespace), &result));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketParameterDefinition{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketFeature<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketFeature)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketFeature<D>::XmlNamespace() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketFeature)->get_XmlNamespace(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlNode) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketFeature<D>::XmlNode() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketFeature)->get_XmlNode(&value));
        return winrt::Windows::Data::Xml::Dom::IXmlNode{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketFeature<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketFeature)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketOption) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketFeature<D>::GetOption(param::hstring const& name, param::hstring const& xmlNamespace) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketFeature)->GetOption(*(void**)(&name), *(void**)(&xmlNamespace), &result));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketOption{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketOption>) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketFeature<D>::Options() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketFeature)->get_Options(&result));
        return winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketOption>{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketOption) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketFeature<D>::GetSelectedOption() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketFeature)->GetSelectedOption(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketOption{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketFeature<D>::SetSelectedOption(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketOption const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketFeature)->SetSelectedOption(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeatureSelectionType) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketFeature<D>::SelectionType() const
    {
        winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeatureSelectionType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketFeature)->get_SelectionType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketOption<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketOption)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketOption<D>::XmlNamespace() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketOption)->get_XmlNamespace(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlNode) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketOption<D>::XmlNode() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketOption)->get_XmlNode(&value));
        return winrt::Windows::Data::Xml::Dom::IXmlNode{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketOption<D>::DisplayName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketOption)->get_DisplayName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlNode) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketOption<D>::GetPropertyNode(param::hstring const& name, param::hstring const& xmlNamespace) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketOption)->GetPropertyNode(*(void**)(&name), *(void**)(&xmlNamespace), &result));
        return winrt::Windows::Data::Xml::Dom::IXmlNode{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlNode) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketOption<D>::GetScoredPropertyNode(param::hstring const& name, param::hstring const& xmlNamespace) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketOption)->GetScoredPropertyNode(*(void**)(&name), *(void**)(&xmlNamespace), &result));
        return winrt::Windows::Data::Xml::Dom::IXmlNode{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketValue) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketOption<D>::GetPropertyValue(param::hstring const& name, param::hstring const& xmlNamespace) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketOption)->GetPropertyValue(*(void**)(&name), *(void**)(&xmlNamespace), &result));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketValue) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketOption<D>::GetScoredPropertyValue(param::hstring const& name, param::hstring const& xmlNamespace) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketOption)->GetScoredPropertyValue(*(void**)(&name), *(void**)(&xmlNamespace), &result));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketValue{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketParameterDefinition<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterDefinition)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketParameterDefinition<D>::XmlNamespace() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterDefinition)->get_XmlNamespace(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlNode) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketParameterDefinition<D>::XmlNode() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterDefinition)->get_XmlNode(&value));
        return winrt::Windows::Data::Xml::Dom::IXmlNode{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketParameterDataType) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketParameterDefinition<D>::DataType() const
    {
        winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketParameterDataType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterDefinition)->get_DataType(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketParameterDefinition<D>::UnitType() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterDefinition)->get_UnitType(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketParameterDefinition<D>::RangeMin() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterDefinition)->get_RangeMin(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketParameterDefinition<D>::RangeMax() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterDefinition)->get_RangeMax(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketParameterInitializer<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterInitializer)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketParameterInitializer<D>::XmlNamespace() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterInitializer)->get_XmlNamespace(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlNode) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketParameterInitializer<D>::XmlNode() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterInitializer)->get_XmlNode(&value));
        return winrt::Windows::Data::Xml::Dom::IXmlNode{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketParameterInitializer<D>::Value(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketValue const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterInitializer)->put_Value(*(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketValue) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketParameterInitializer<D>::Value() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterInitializer)->get_Value(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketValue{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketValueType) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketValue<D>::Type() const
    {
        winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketValueType value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketValue)->get_Type(reinterpret_cast<int32_t*>(&value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(int32_t) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketValue<D>::GetValueAsInteger() const
    {
        int32_t value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketValue)->GetValueAsInteger(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Graphics_Printing_PrintTicket_IPrintTicketValue<D>::GetValueAsString() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketValue)->GetValueAsString(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicket<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicket<D>::XmlNamespace() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket)->get_XmlNamespace(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlNode) consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicket<D>::XmlNode() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket)->get_XmlNode(&value));
        return winrt::Windows::Data::Xml::Dom::IXmlNode{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketCapabilities) consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicket<D>::GetCapabilities() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket)->GetCapabilities(&result));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketCapabilities{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicket<D>::DocumentBindingFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket)->get_DocumentBindingFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicket<D>::DocumentCollateFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket)->get_DocumentCollateFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicket<D>::DocumentDuplexFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket)->get_DocumentDuplexFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicket<D>::DocumentHolePunchFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket)->get_DocumentHolePunchFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicket<D>::DocumentInputBinFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket)->get_DocumentInputBinFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicket<D>::DocumentNUpFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket)->get_DocumentNUpFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicket<D>::DocumentStapleFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket)->get_DocumentStapleFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicket<D>::JobPasscodeFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket)->get_JobPasscodeFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicket<D>::PageBorderlessFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket)->get_PageBorderlessFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicket<D>::PageMediaSizeFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket)->get_PageMediaSizeFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicket<D>::PageMediaTypeFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket)->get_PageMediaTypeFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicket<D>::PageOrientationFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket)->get_PageOrientationFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicket<D>::PageOutputColorFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket)->get_PageOutputColorFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicket<D>::PageOutputQualityFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket)->get_PageOutputQualityFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicket<D>::PageResolutionFeature() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket)->get_PageResolutionFeature(&value));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature) consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicket<D>::GetFeature(param::hstring const& name, param::hstring const& xmlNamespace) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket)->GetFeature(*(void**)(&name), *(void**)(&xmlNamespace), &result));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicket<D>::NotifyXmlChangedAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket)->NotifyXmlChangedAsync(&operation));
        return winrt::Windows::Foundation::IAsyncAction{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicketValidationResult>) consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicket<D>::ValidateAsync() const
    {
        void* operation{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket)->ValidateAsync(&operation));
        return winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicketValidationResult>{ operation, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketParameterInitializer) consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicket<D>::GetParameterInitializer(param::hstring const& name, param::hstring const& xmlNamespace) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket)->GetParameterInitializer(*(void**)(&name), *(void**)(&xmlNamespace), &result));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketParameterInitializer{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketParameterInitializer) consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicket<D>::SetParameterInitializerAsInteger(param::hstring const& name, param::hstring const& xmlNamespace, int32_t integerValue) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket)->SetParameterInitializerAsInteger(*(void**)(&name), *(void**)(&xmlNamespace), integerValue, &result));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketParameterInitializer{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketParameterInitializer) consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicket<D>::SetParameterInitializerAsString(param::hstring const& name, param::hstring const& xmlNamespace, param::hstring const& stringValue) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket)->SetParameterInitializerAsString(*(void**)(&name), *(void**)(&xmlNamespace), *(void**)(&stringValue), &result));
        return winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketParameterInitializer{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket) consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicket<D>::MergeAndValidateTicket(winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket const& deltaShemaTicket) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket)->MergeAndValidateTicket(*(void**)(&deltaShemaTicket), &result));
        return winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicketValidationResult<D>::Validated() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicketValidationResult)->get_Validated(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::hresult) consume_Windows_Graphics_Printing_PrintTicket_IWorkflowPrintTicketValidationResult<D>::ExtendedError() const
    {
        winrt::hresult value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicketValidationResult)->get_ExtendedError(put_abi(value)));
        return value;
    }
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities> : produce_base<D, winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XmlNamespace(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().XmlNamespace());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XmlNode(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Data::Xml::Dom::IXmlNode>(this->shim().XmlNode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DocumentBindingFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().DocumentBindingFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DocumentCollateFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().DocumentCollateFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DocumentDuplexFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().DocumentDuplexFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DocumentHolePunchFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().DocumentHolePunchFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DocumentInputBinFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().DocumentInputBinFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DocumentNUpFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().DocumentNUpFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DocumentStapleFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().DocumentStapleFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_JobPasscodeFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().JobPasscodeFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PageBorderlessFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().PageBorderlessFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PageMediaSizeFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().PageMediaSizeFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PageMediaTypeFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().PageMediaTypeFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PageOrientationFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().PageOrientationFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PageOutputColorFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().PageOutputColorFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PageOutputQualityFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().PageOutputQualityFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PageResolutionFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().PageResolutionFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetFeature(void* name, void* xmlNamespace, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().GetFeature(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&xmlNamespace)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetParameterDefinition(void* name, void* xmlNamespace, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketParameterDefinition>(this->shim().GetParameterDefinition(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&xmlNamespace)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketFeature> : produce_base<D, winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketFeature>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XmlNamespace(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().XmlNamespace());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XmlNode(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Data::Xml::Dom::IXmlNode>(this->shim().XmlNode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetOption(void* name, void* xmlNamespace, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketOption>(this->shim().GetOption(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&xmlNamespace)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Options(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketOption>>(this->shim().Options());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetSelectedOption(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketOption>(this->shim().GetSelectedOption());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetSelectedOption(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetSelectedOption(*reinterpret_cast<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketOption const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_SelectionType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeatureSelectionType>(this->shim().SelectionType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketOption> : produce_base<D, winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketOption>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XmlNamespace(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().XmlNamespace());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XmlNode(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Data::Xml::Dom::IXmlNode>(this->shim().XmlNode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DisplayName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().DisplayName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPropertyNode(void* name, void* xmlNamespace, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Data::Xml::Dom::IXmlNode>(this->shim().GetPropertyNode(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&xmlNamespace)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetScoredPropertyNode(void* name, void* xmlNamespace, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Data::Xml::Dom::IXmlNode>(this->shim().GetScoredPropertyNode(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&xmlNamespace)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetPropertyValue(void* name, void* xmlNamespace, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketValue>(this->shim().GetPropertyValue(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&xmlNamespace)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetScoredPropertyValue(void* name, void* xmlNamespace, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketValue>(this->shim().GetScoredPropertyValue(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&xmlNamespace)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterDefinition> : produce_base<D, winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterDefinition>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XmlNamespace(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().XmlNamespace());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XmlNode(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Data::Xml::Dom::IXmlNode>(this->shim().XmlNode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DataType(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketParameterDataType>(this->shim().DataType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UnitType(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().UnitType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RangeMin(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().RangeMin());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_RangeMax(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().RangeMax());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterInitializer> : produce_base<D, winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterInitializer>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XmlNamespace(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().XmlNamespace());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XmlNode(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Data::Xml::Dom::IXmlNode>(this->shim().XmlNode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall put_Value(void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Value(*reinterpret_cast<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketValue const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Value(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketValue>(this->shim().Value());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketValue> : produce_base<D, winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketValue>
    {
        int32_t __stdcall get_Type(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketValueType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetValueAsInteger(int32_t* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<int32_t>(this->shim().GetValueAsInteger());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetValueAsString(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().GetValueAsString());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket> : produce_base<D, winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket>
    {
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XmlNamespace(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().XmlNamespace());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_XmlNode(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Data::Xml::Dom::IXmlNode>(this->shim().XmlNode());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetCapabilities(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketCapabilities>(this->shim().GetCapabilities());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DocumentBindingFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().DocumentBindingFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DocumentCollateFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().DocumentCollateFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DocumentDuplexFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().DocumentDuplexFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DocumentHolePunchFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().DocumentHolePunchFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DocumentInputBinFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().DocumentInputBinFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DocumentNUpFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().DocumentNUpFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_DocumentStapleFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().DocumentStapleFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_JobPasscodeFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().JobPasscodeFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PageBorderlessFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().PageBorderlessFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PageMediaSizeFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().PageMediaSizeFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PageMediaTypeFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().PageMediaTypeFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PageOrientationFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().PageOrientationFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PageOutputColorFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().PageOutputColorFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PageOutputQualityFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().PageOutputQualityFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_PageResolutionFeature(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().PageResolutionFeature());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetFeature(void* name, void* xmlNamespace, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature>(this->shim().GetFeature(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&xmlNamespace)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall NotifyXmlChangedAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncAction>(this->shim().NotifyXmlChangedAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ValidateAsync(void** operation) noexcept final try
        {
            clear_abi(operation);
            typename D::abi_guard guard(this->shim());
            *operation = detach_from<winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicketValidationResult>>(this->shim().ValidateAsync());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetParameterInitializer(void* name, void* xmlNamespace, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketParameterInitializer>(this->shim().GetParameterInitializer(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&xmlNamespace)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetParameterInitializerAsInteger(void* name, void* xmlNamespace, int32_t integerValue, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketParameterInitializer>(this->shim().SetParameterInitializerAsInteger(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&xmlNamespace), integerValue));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetParameterInitializerAsString(void* name, void* xmlNamespace, void* stringValue, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketParameterInitializer>(this->shim().SetParameterInitializerAsString(*reinterpret_cast<hstring const*>(&name), *reinterpret_cast<hstring const*>(&xmlNamespace), *reinterpret_cast<hstring const*>(&stringValue)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall MergeAndValidateTicket(void* deltaShemaTicket, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket>(this->shim().MergeAndValidateTicket(*reinterpret_cast<winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket const*>(&deltaShemaTicket)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicketValidationResult> : produce_base<D, winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicketValidationResult>
    {
        int32_t __stdcall get_Validated(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().Validated());
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
    };
#endif
}
WINRT_EXPORT namespace winrt::Windows::Graphics::Printing::PrintTicket
{
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketFeature> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketOption> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterDefinition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketParameterInitializer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintTicket::IPrintTicketValue> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicket> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintTicket::IWorkflowPrintTicketValidationResult> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketCapabilities> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketFeature> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketOption> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketParameterDefinition> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketParameterInitializer> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintTicket::PrintTicketValue> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicket> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::Graphics::Printing::PrintTicket::WorkflowPrintTicketValidationResult> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
