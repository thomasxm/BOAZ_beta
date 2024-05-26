// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Xaml_Markup_H
#define WINRT_Windows_UI_Xaml_Markup_H
#include "winrt/base.h"
static_assert(winrt::check_version(CPPWINRT_VERSION, "2.0.220110.5"), "Mismatched C++/WinRT headers.");
#define CPPWINRT_VERSION "2.0.220110.5"
#include "winrt/Windows.UI.Xaml.h"
#include "winrt/impl/Windows.Foundation.2.h"
#include "winrt/impl/Windows.Foundation.Collections.2.h"
#include "winrt/impl/Windows.Storage.Streams.2.h"
#include "winrt/impl/Windows.UI.Xaml.2.h"
#include "winrt/impl/Windows.UI.Xaml.Interop.2.h"
#include "winrt/impl/Windows.UI.Xaml.Markup.2.h"
namespace winrt::impl
{
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Markup_IComponentConnector<D>::Connect(int32_t connectionId, winrt::Windows::Foundation::IInspectable const& target) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IComponentConnector)->Connect(connectionId, *(void**)(&target)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Markup::IComponentConnector) consume_Windows_UI_Xaml_Markup_IComponentConnector2<D>::GetBindingConnector(int32_t connectionId, winrt::Windows::Foundation::IInspectable const& target) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IComponentConnector2)->GetBindingConnector(connectionId, *(void**)(&target), &result));
        return winrt::Windows::UI::Xaml::Markup::IComponentConnector{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Markup_IDataTemplateComponent<D>::Recycle() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IDataTemplateComponent)->Recycle());
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Markup_IDataTemplateComponent<D>::ProcessBindings(winrt::Windows::Foundation::IInspectable const& item, int32_t itemIndex, int32_t phase, int32_t& nextPhase) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IDataTemplateComponent)->ProcessBindings(*(void**)(&item), itemIndex, phase, &nextPhase));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Markup::MarkupExtension) consume_Windows_UI_Xaml_Markup_IMarkupExtensionFactory<D>::CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IMarkupExtensionFactory)->CreateInstance(*(void**)(&baseInterface), impl::bind_out(innerInterface), &value));
        return winrt::Windows::UI::Xaml::Markup::MarkupExtension{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Markup_IMarkupExtensionOverrides<D>::ProvideValue() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IMarkupExtensionOverrides)->ProvideValue(&result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Markup::XamlBinaryWriterErrorInformation) consume_Windows_UI_Xaml_Markup_IXamlBinaryWriterStatics<D>::Write(param::vector<winrt::Windows::Storage::Streams::IRandomAccessStream> const& inputStreams, param::vector<winrt::Windows::Storage::Streams::IRandomAccessStream> const& outputStreams, winrt::Windows::UI::Xaml::Markup::IXamlMetadataProvider const& xamlMetadataProvider) const
    {
        winrt::Windows::UI::Xaml::Markup::XamlBinaryWriterErrorInformation result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlBinaryWriterStatics)->Write(*(void**)(&inputStreams), *(void**)(&outputStreams), *(void**)(&xamlMetadataProvider), put_abi(result)));
        return result;
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Markup_IXamlBindScopeDiagnostics<D>::Disable(int32_t lineNumber, int32_t columnNumber) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlBindScopeDiagnostics)->Disable(lineNumber, columnNumber));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::DataTemplateComponentProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->get_DataTemplateComponentProperty(&value));
        return winrt::Windows::UI::Xaml::DependencyProperty{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Markup::IDataTemplateComponent) consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::GetDataTemplateComponent(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->GetDataTemplateComponent(*(void**)(&element), &result));
        return winrt::Windows::UI::Xaml::Markup::IDataTemplateComponent{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetDataTemplateComponent(winrt::Windows::UI::Xaml::DependencyObject const& element, winrt::Windows::UI::Xaml::Markup::IDataTemplateComponent const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetDataTemplateComponent(*(void**)(&element), *(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SuspendRendering(winrt::Windows::UI::Xaml::UIElement const& target) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SuspendRendering(*(void**)(&target)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::ResumeRendering(winrt::Windows::UI::Xaml::UIElement const& target) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->ResumeRendering(*(void**)(&target)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::ConvertValue(winrt::Windows::UI::Xaml::Interop::TypeName const& type, winrt::Windows::Foundation::IInspectable const& value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->ConvertValue(impl::bind_in(type), *(void**)(&value), &result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromString(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, param::hstring const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromString(*(void**)(&dependencyObject), *(void**)(&propertyToSet), *(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromBoolean(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, bool value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromBoolean(*(void**)(&dependencyObject), *(void**)(&propertyToSet), value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromChar16(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, char16_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromChar16(*(void**)(&dependencyObject), *(void**)(&propertyToSet), value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromDateTime(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, winrt::Windows::Foundation::DateTime const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromDateTime(*(void**)(&dependencyObject), *(void**)(&propertyToSet), impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromDouble(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, double value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromDouble(*(void**)(&dependencyObject), *(void**)(&propertyToSet), value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromInt32(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, int32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromInt32(*(void**)(&dependencyObject), *(void**)(&propertyToSet), value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromUInt32(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, uint32_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromUInt32(*(void**)(&dependencyObject), *(void**)(&propertyToSet), value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromInt64(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, int64_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromInt64(*(void**)(&dependencyObject), *(void**)(&propertyToSet), value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromUInt64(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, uint64_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromUInt64(*(void**)(&dependencyObject), *(void**)(&propertyToSet), value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromSingle(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, float value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromSingle(*(void**)(&dependencyObject), *(void**)(&propertyToSet), value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromPoint(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, winrt::Windows::Foundation::Point const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromPoint(*(void**)(&dependencyObject), *(void**)(&propertyToSet), impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromRect(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, winrt::Windows::Foundation::Rect const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromRect(*(void**)(&dependencyObject), *(void**)(&propertyToSet), impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromSize(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, winrt::Windows::Foundation::Size const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromSize(*(void**)(&dependencyObject), *(void**)(&propertyToSet), impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromTimeSpan(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, winrt::Windows::Foundation::TimeSpan const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromTimeSpan(*(void**)(&dependencyObject), *(void**)(&propertyToSet), impl::bind_in(value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromByte(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, uint8_t value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromByte(*(void**)(&dependencyObject), *(void**)(&propertyToSet), value));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromUri(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, winrt::Windows::Foundation::Uri const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromUri(*(void**)(&dependencyObject), *(void**)(&propertyToSet), *(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Markup_IXamlBindingHelperStatics<D>::SetPropertyFromObject(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlBindingHelperStatics)->SetPropertyFromObject(*(void**)(&dependencyObject), *(void**)(&propertyToSet), *(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Markup_IXamlMarkupHelperStatics<D>::UnloadObject(winrt::Windows::UI::Xaml::DependencyObject const& element) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlMarkupHelperStatics)->UnloadObject(*(void**)(&element)));
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Markup_IXamlMember<D>::IsAttachable() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlMember)->get_IsAttachable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Markup_IXamlMember<D>::IsDependencyProperty() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlMember)->get_IsDependencyProperty(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Markup_IXamlMember<D>::IsReadOnly() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlMember)->get_IsReadOnly(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Markup_IXamlMember<D>::Name() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlMember)->get_Name(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Markup::IXamlType) consume_Windows_UI_Xaml_Markup_IXamlMember<D>::TargetType() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlMember)->get_TargetType(&value));
        return winrt::Windows::UI::Xaml::Markup::IXamlType{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Markup::IXamlType) consume_Windows_UI_Xaml_Markup_IXamlMember<D>::Type() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlMember)->get_Type(&value));
        return winrt::Windows::UI::Xaml::Markup::IXamlType{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Markup_IXamlMember<D>::GetValue(winrt::Windows::Foundation::IInspectable const& instance) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlMember)->GetValue(*(void**)(&instance), &result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Markup_IXamlMember<D>::SetValue(winrt::Windows::Foundation::IInspectable const& instance, winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlMember)->SetValue(*(void**)(&instance), *(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Markup::IXamlType) consume_Windows_UI_Xaml_Markup_IXamlMetadataProvider<D>::GetXamlType(winrt::Windows::UI::Xaml::Interop::TypeName const& type) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlMetadataProvider)->GetXamlType(impl::bind_in(type), &result));
        return winrt::Windows::UI::Xaml::Markup::IXamlType{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Markup::IXamlType) consume_Windows_UI_Xaml_Markup_IXamlMetadataProvider<D>::GetXamlType(param::hstring const& fullName) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlMetadataProvider)->GetXamlTypeByFullName(*(void**)(&fullName), &result));
        return winrt::Windows::UI::Xaml::Markup::IXamlType{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(com_array<winrt::Windows::UI::Xaml::Markup::XmlnsDefinition>) consume_Windows_UI_Xaml_Markup_IXamlMetadataProvider<D>::GetXmlnsDefinitions() const
    {
        uint32_t result_impl_size{};
        struct struct_Windows_UI_Xaml_Markup_XmlnsDefinition* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlMetadataProvider)->GetXmlnsDefinitions(&result_impl_size, &result));
        return com_array<winrt::Windows::UI::Xaml::Markup::XmlnsDefinition>{ result, result_impl_size, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Markup_IXamlReaderStatics<D>::Load(param::hstring const& xaml) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlReaderStatics)->Load(*(void**)(&xaml), &result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Markup_IXamlReaderStatics<D>::LoadWithInitialTemplateValidation(param::hstring const& xaml) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlReaderStatics)->LoadWithInitialTemplateValidation(*(void**)(&xaml), &result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Markup::IXamlType) consume_Windows_UI_Xaml_Markup_IXamlType<D>::BaseType() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlType)->get_BaseType(&value));
        return winrt::Windows::UI::Xaml::Markup::IXamlType{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Markup::IXamlMember) consume_Windows_UI_Xaml_Markup_IXamlType<D>::ContentProperty() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlType)->get_ContentProperty(&value));
        return winrt::Windows::UI::Xaml::Markup::IXamlMember{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(hstring) consume_Windows_UI_Xaml_Markup_IXamlType<D>::FullName() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlType)->get_FullName(&value));
        return hstring{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Markup_IXamlType<D>::IsArray() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlType)->get_IsArray(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Markup_IXamlType<D>::IsCollection() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlType)->get_IsCollection(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Markup_IXamlType<D>::IsConstructible() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlType)->get_IsConstructible(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Markup_IXamlType<D>::IsDictionary() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlType)->get_IsDictionary(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Markup_IXamlType<D>::IsMarkupExtension() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlType)->get_IsMarkupExtension(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(bool) consume_Windows_UI_Xaml_Markup_IXamlType<D>::IsBindable() const
    {
        bool value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlType)->get_IsBindable(&value));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Markup::IXamlType) consume_Windows_UI_Xaml_Markup_IXamlType<D>::ItemType() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlType)->get_ItemType(&value));
        return winrt::Windows::UI::Xaml::Markup::IXamlType{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Markup::IXamlType) consume_Windows_UI_Xaml_Markup_IXamlType<D>::KeyType() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlType)->get_KeyType(&value));
        return winrt::Windows::UI::Xaml::Markup::IXamlType{ value, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Interop::TypeName) consume_Windows_UI_Xaml_Markup_IXamlType<D>::UnderlyingType() const
    {
        winrt::Windows::UI::Xaml::Interop::TypeName value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlType)->get_UnderlyingType(put_abi(value)));
        return value;
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Markup_IXamlType<D>::ActivateInstance() const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlType)->ActivateInstance(&result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) consume_Windows_UI_Xaml_Markup_IXamlType<D>::CreateFromString(param::hstring const& value) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlType)->CreateFromString(*(void**)(&value), &result));
        return winrt::Windows::Foundation::IInspectable{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Markup::IXamlMember) consume_Windows_UI_Xaml_Markup_IXamlType<D>::GetMember(param::hstring const& name) const
    {
        void* result{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlType)->GetMember(*(void**)(&name), &result));
        return winrt::Windows::UI::Xaml::Markup::IXamlMember{ result, take_ownership_from_abi };
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Markup_IXamlType<D>::AddToVector(winrt::Windows::Foundation::IInspectable const& instance, winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlType)->AddToVector(*(void**)(&instance), *(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Markup_IXamlType<D>::AddToMap(winrt::Windows::Foundation::IInspectable const& instance, winrt::Windows::Foundation::IInspectable const& key, winrt::Windows::Foundation::IInspectable const& value) const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlType)->AddToMap(*(void**)(&instance), *(void**)(&key), *(void**)(&value)));
    }
    template <typename D> WINRT_IMPL_AUTO(void) consume_Windows_UI_Xaml_Markup_IXamlType<D>::RunInitializer() const
    {
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlType)->RunInitializer());
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Markup::IXamlType) consume_Windows_UI_Xaml_Markup_IXamlType2<D>::BoxedType() const
    {
        void* value{};
        check_hresult(WINRT_IMPL_SHIM(winrt::Windows::UI::Xaml::Markup::IXamlType2)->get_BoxedType(&value));
        return winrt::Windows::UI::Xaml::Markup::IXamlType{ value, take_ownership_from_abi };
    }
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Markup::IComponentConnector> : produce_base<D, winrt::Windows::UI::Xaml::Markup::IComponentConnector>
    {
        int32_t __stdcall Connect(int32_t connectionId, void* target) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Connect(connectionId, *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&target));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Markup::IComponentConnector2> : produce_base<D, winrt::Windows::UI::Xaml::Markup::IComponentConnector2>
    {
        int32_t __stdcall GetBindingConnector(int32_t connectionId, void* target, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Markup::IComponentConnector>(this->shim().GetBindingConnector(connectionId, *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&target)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Markup::IDataTemplateComponent> : produce_base<D, winrt::Windows::UI::Xaml::Markup::IDataTemplateComponent>
    {
        int32_t __stdcall Recycle() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Recycle();
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ProcessBindings(void* item, int32_t itemIndex, int32_t phase, int32_t* nextPhase) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ProcessBindings(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&item), itemIndex, phase, *nextPhase);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Markup::IMarkupExtension> : produce_base<D, winrt::Windows::UI::Xaml::Markup::IMarkupExtension>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Markup::IMarkupExtensionFactory> : produce_base<D, winrt::Windows::UI::Xaml::Markup::IMarkupExtensionFactory>
    {
        int32_t __stdcall CreateInstance(void* baseInterface, void** innerInterface, void** value) noexcept final try
        {
            if (innerInterface) *innerInterface = nullptr;
            winrt::Windows::Foundation::IInspectable winrt_impl_innerInterface;
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Markup::MarkupExtension>(this->shim().CreateInstance(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&baseInterface), winrt_impl_innerInterface));
                if (innerInterface) *innerInterface = detach_abi(winrt_impl_innerInterface);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Markup::IMarkupExtensionOverrides> : produce_base<D, winrt::Windows::UI::Xaml::Markup::IMarkupExtensionOverrides>
    {
        int32_t __stdcall ProvideValue(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().ProvideValue());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Markup::IXamlBinaryWriter> : produce_base<D, winrt::Windows::UI::Xaml::Markup::IXamlBinaryWriter>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Markup::IXamlBinaryWriterStatics> : produce_base<D, winrt::Windows::UI::Xaml::Markup::IXamlBinaryWriterStatics>
    {
        int32_t __stdcall Write(void* inputStreams, void* outputStreams, void* xamlMetadataProvider, struct struct_Windows_UI_Xaml_Markup_XamlBinaryWriterErrorInformation* result) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Markup::XamlBinaryWriterErrorInformation>(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Markup::XamlBinaryWriterErrorInformation>(this->shim().Write(*reinterpret_cast<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::Streams::IRandomAccessStream> const*>(&inputStreams), *reinterpret_cast<winrt::Windows::Foundation::Collections::IVector<winrt::Windows::Storage::Streams::IRandomAccessStream> const*>(&outputStreams), *reinterpret_cast<winrt::Windows::UI::Xaml::Markup::IXamlMetadataProvider const*>(&xamlMetadataProvider)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Markup::IXamlBindScopeDiagnostics> : produce_base<D, winrt::Windows::UI::Xaml::Markup::IXamlBindScopeDiagnostics>
    {
        int32_t __stdcall Disable(int32_t lineNumber, int32_t columnNumber) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().Disable(lineNumber, columnNumber);
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Markup::IXamlBindingHelper> : produce_base<D, winrt::Windows::UI::Xaml::Markup::IXamlBindingHelper>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Markup::IXamlBindingHelperStatics> : produce_base<D, winrt::Windows::UI::Xaml::Markup::IXamlBindingHelperStatics>
    {
        int32_t __stdcall get_DataTemplateComponentProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::DependencyProperty>(this->shim().DataTemplateComponentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetDataTemplateComponent(void* element, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Markup::IDataTemplateComponent>(this->shim().GetDataTemplateComponent(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetDataTemplateComponent(void* element, void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetDataTemplateComponent(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element), *reinterpret_cast<winrt::Windows::UI::Xaml::Markup::IDataTemplateComponent const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SuspendRendering(void* target) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SuspendRendering(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&target));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ResumeRendering(void* target) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().ResumeRendering(*reinterpret_cast<winrt::Windows::UI::Xaml::UIElement const*>(&target));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ConvertValue(struct struct_Windows_UI_Xaml_Interop_TypeName type, void* value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().ConvertValue(*reinterpret_cast<winrt::Windows::UI::Xaml::Interop::TypeName const*>(&type), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPropertyFromString(void* dependencyObject, void* propertyToSet, void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPropertyFromString(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), *reinterpret_cast<hstring const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPropertyFromBoolean(void* dependencyObject, void* propertyToSet, bool value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPropertyFromBoolean(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPropertyFromChar16(void* dependencyObject, void* propertyToSet, char16_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPropertyFromChar16(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPropertyFromDateTime(void* dependencyObject, void* propertyToSet, int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPropertyFromDateTime(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), *reinterpret_cast<winrt::Windows::Foundation::DateTime const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPropertyFromDouble(void* dependencyObject, void* propertyToSet, double value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPropertyFromDouble(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPropertyFromInt32(void* dependencyObject, void* propertyToSet, int32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPropertyFromInt32(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPropertyFromUInt32(void* dependencyObject, void* propertyToSet, uint32_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPropertyFromUInt32(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPropertyFromInt64(void* dependencyObject, void* propertyToSet, int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPropertyFromInt64(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPropertyFromUInt64(void* dependencyObject, void* propertyToSet, uint64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPropertyFromUInt64(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPropertyFromSingle(void* dependencyObject, void* propertyToSet, float value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPropertyFromSingle(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPropertyFromPoint(void* dependencyObject, void* propertyToSet, winrt::Windows::Foundation::Point value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPropertyFromPoint(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), *reinterpret_cast<winrt::Windows::Foundation::Point const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPropertyFromRect(void* dependencyObject, void* propertyToSet, winrt::Windows::Foundation::Rect value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPropertyFromRect(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), *reinterpret_cast<winrt::Windows::Foundation::Rect const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPropertyFromSize(void* dependencyObject, void* propertyToSet, winrt::Windows::Foundation::Size value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPropertyFromSize(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), *reinterpret_cast<winrt::Windows::Foundation::Size const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPropertyFromTimeSpan(void* dependencyObject, void* propertyToSet, int64_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPropertyFromTimeSpan(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), *reinterpret_cast<winrt::Windows::Foundation::TimeSpan const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPropertyFromByte(void* dependencyObject, void* propertyToSet, uint8_t value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPropertyFromByte(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), value);
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPropertyFromUri(void* dependencyObject, void* propertyToSet, void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPropertyFromUri(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), *reinterpret_cast<winrt::Windows::Foundation::Uri const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetPropertyFromObject(void* dependencyObject, void* propertyToSet, void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetPropertyFromObject(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&dependencyObject), *reinterpret_cast<winrt::Windows::UI::Xaml::DependencyProperty const*>(&propertyToSet), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Markup::IXamlMarkupHelper> : produce_base<D, winrt::Windows::UI::Xaml::Markup::IXamlMarkupHelper>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Markup::IXamlMarkupHelperStatics> : produce_base<D, winrt::Windows::UI::Xaml::Markup::IXamlMarkupHelperStatics>
    {
        int32_t __stdcall UnloadObject(void* element) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().UnloadObject(*reinterpret_cast<winrt::Windows::UI::Xaml::DependencyObject const*>(&element));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Markup::IXamlMember> : produce_base<D, winrt::Windows::UI::Xaml::Markup::IXamlMember>
    {
        int32_t __stdcall get_IsAttachable(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsAttachable());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDependencyProperty(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDependencyProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsReadOnly(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsReadOnly());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Name(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().Name());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_TargetType(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Markup::IXamlType>(this->shim().TargetType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_Type(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Markup::IXamlType>(this->shim().Type());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetValue(void* instance, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().GetValue(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&instance)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall SetValue(void* instance, void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().SetValue(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&instance), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Markup::IXamlMetadataProvider> : produce_base<D, winrt::Windows::UI::Xaml::Markup::IXamlMetadataProvider>
    {
        int32_t __stdcall GetXamlType(struct struct_Windows_UI_Xaml_Interop_TypeName type, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Markup::IXamlType>(this->shim().GetXamlType(*reinterpret_cast<winrt::Windows::UI::Xaml::Interop::TypeName const*>(&type)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetXamlTypeByFullName(void* fullName, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Markup::IXamlType>(this->shim().GetXamlType(*reinterpret_cast<hstring const*>(&fullName)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetXmlnsDefinitions(uint32_t* __resultSize, struct struct_Windows_UI_Xaml_Markup_XmlnsDefinition** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            std::tie(*__resultSize, *result) = detach_abi(this->shim().GetXmlnsDefinitions());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Markup::IXamlReader> : produce_base<D, winrt::Windows::UI::Xaml::Markup::IXamlReader>
    {
    };
#endif
#ifndef WINRT_LEAN_AND_MEAN
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Markup::IXamlReaderStatics> : produce_base<D, winrt::Windows::UI::Xaml::Markup::IXamlReaderStatics>
    {
        int32_t __stdcall Load(void* xaml, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().Load(*reinterpret_cast<hstring const*>(&xaml)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall LoadWithInitialTemplateValidation(void* xaml, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().LoadWithInitialTemplateValidation(*reinterpret_cast<hstring const*>(&xaml)));
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
#endif
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Markup::IXamlType> : produce_base<D, winrt::Windows::UI::Xaml::Markup::IXamlType>
    {
        int32_t __stdcall get_BaseType(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Markup::IXamlType>(this->shim().BaseType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ContentProperty(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Markup::IXamlMember>(this->shim().ContentProperty());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_FullName(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<hstring>(this->shim().FullName());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsArray(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsArray());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsCollection(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsCollection());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsConstructible(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsConstructible());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsDictionary(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsDictionary());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsMarkupExtension(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsMarkupExtension());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_IsBindable(bool* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            *value = detach_from<bool>(this->shim().IsBindable());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_ItemType(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Markup::IXamlType>(this->shim().ItemType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_KeyType(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Markup::IXamlType>(this->shim().KeyType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall get_UnderlyingType(struct struct_Windows_UI_Xaml_Interop_TypeName* value) noexcept final try
        {
            zero_abi<winrt::Windows::UI::Xaml::Interop::TypeName>(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Interop::TypeName>(this->shim().UnderlyingType());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall ActivateInstance(void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().ActivateInstance());
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall CreateFromString(void* value, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::Foundation::IInspectable>(this->shim().CreateFromString(*reinterpret_cast<hstring const*>(&value)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall GetMember(void* name, void** result) noexcept final try
        {
            clear_abi(result);
            typename D::abi_guard guard(this->shim());
            *result = detach_from<winrt::Windows::UI::Xaml::Markup::IXamlMember>(this->shim().GetMember(*reinterpret_cast<hstring const*>(&name)));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddToVector(void* instance, void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddToVector(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&instance), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall AddToMap(void* instance, void* key, void* value) noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().AddToMap(*reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&instance), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&key), *reinterpret_cast<winrt::Windows::Foundation::IInspectable const*>(&value));
            return 0;
        }
        catch (...) { return to_hresult(); }
        int32_t __stdcall RunInitializer() noexcept final try
        {
            typename D::abi_guard guard(this->shim());
            this->shim().RunInitializer();
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
    template <typename D>
    struct produce<D, winrt::Windows::UI::Xaml::Markup::IXamlType2> : produce_base<D, winrt::Windows::UI::Xaml::Markup::IXamlType2>
    {
        int32_t __stdcall get_BoxedType(void** value) noexcept final try
        {
            clear_abi(value);
            typename D::abi_guard guard(this->shim());
            *value = detach_from<winrt::Windows::UI::Xaml::Markup::IXamlType>(this->shim().BoxedType());
            return 0;
        }
        catch (...) { return to_hresult(); }
    };
template <typename T, typename D>
struct __declspec(empty_bases) produce_dispatch_to_overridable<T, D, winrt::Windows::UI::Xaml::Markup::IMarkupExtensionOverrides>
    : produce_dispatch_to_overridable_base<T, D, winrt::Windows::UI::Xaml::Markup::IMarkupExtensionOverrides>
{
    auto ProvideValue()
    {
        if (auto overridable = this->shim_overridable())
        {
            return overridable.ProvideValue();
        }

        return this->shim().ProvideValue();
    }
};
}
WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Markup
{
    inline MarkupExtension::MarkupExtension()
    {
        winrt::Windows::Foundation::IInspectable baseInterface, innerInterface;
        *this = impl::call_factory<MarkupExtension, IMarkupExtensionFactory>([&](IMarkupExtensionFactory const& f) { return f.CreateInstance(baseInterface, innerInterface); });
    }
    inline auto XamlBinaryWriter::Write(param::vector<winrt::Windows::Storage::Streams::IRandomAccessStream> const& inputStreams, param::vector<winrt::Windows::Storage::Streams::IRandomAccessStream> const& outputStreams, winrt::Windows::UI::Xaml::Markup::IXamlMetadataProvider const& xamlMetadataProvider)
    {
        return impl::call_factory<XamlBinaryWriter, IXamlBinaryWriterStatics>([&](IXamlBinaryWriterStatics const& f) { return f.Write(inputStreams, outputStreams, xamlMetadataProvider); });
    }
    inline auto XamlBindingHelper::DataTemplateComponentProperty()
    {
        return impl::call_factory_cast<winrt::Windows::UI::Xaml::DependencyProperty(*)(IXamlBindingHelperStatics const&), XamlBindingHelper, IXamlBindingHelperStatics>([](IXamlBindingHelperStatics const& f) { return f.DataTemplateComponentProperty(); });
    }
    inline auto XamlBindingHelper::GetDataTemplateComponent(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        return impl::call_factory<XamlBindingHelper, IXamlBindingHelperStatics>([&](IXamlBindingHelperStatics const& f) { return f.GetDataTemplateComponent(element); });
    }
    inline auto XamlBindingHelper::SetDataTemplateComponent(winrt::Windows::UI::Xaml::DependencyObject const& element, winrt::Windows::UI::Xaml::Markup::IDataTemplateComponent const& value)
    {
        impl::call_factory<XamlBindingHelper, IXamlBindingHelperStatics>([&](IXamlBindingHelperStatics const& f) { return f.SetDataTemplateComponent(element, value); });
    }
    inline auto XamlBindingHelper::SuspendRendering(winrt::Windows::UI::Xaml::UIElement const& target)
    {
        impl::call_factory<XamlBindingHelper, IXamlBindingHelperStatics>([&](IXamlBindingHelperStatics const& f) { return f.SuspendRendering(target); });
    }
    inline auto XamlBindingHelper::ResumeRendering(winrt::Windows::UI::Xaml::UIElement const& target)
    {
        impl::call_factory<XamlBindingHelper, IXamlBindingHelperStatics>([&](IXamlBindingHelperStatics const& f) { return f.ResumeRendering(target); });
    }
    inline auto XamlBindingHelper::ConvertValue(winrt::Windows::UI::Xaml::Interop::TypeName const& type, winrt::Windows::Foundation::IInspectable const& value)
    {
        return impl::call_factory<XamlBindingHelper, IXamlBindingHelperStatics>([&](IXamlBindingHelperStatics const& f) { return f.ConvertValue(type, value); });
    }
    inline auto XamlBindingHelper::SetPropertyFromString(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, param::hstring const& value)
    {
        impl::call_factory<XamlBindingHelper, IXamlBindingHelperStatics>([&](IXamlBindingHelperStatics const& f) { return f.SetPropertyFromString(dependencyObject, propertyToSet, value); });
    }
    inline auto XamlBindingHelper::SetPropertyFromBoolean(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, bool value)
    {
        impl::call_factory<XamlBindingHelper, IXamlBindingHelperStatics>([&](IXamlBindingHelperStatics const& f) { return f.SetPropertyFromBoolean(dependencyObject, propertyToSet, value); });
    }
    inline auto XamlBindingHelper::SetPropertyFromChar16(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, char16_t value)
    {
        impl::call_factory<XamlBindingHelper, IXamlBindingHelperStatics>([&](IXamlBindingHelperStatics const& f) { return f.SetPropertyFromChar16(dependencyObject, propertyToSet, value); });
    }
    inline auto XamlBindingHelper::SetPropertyFromDateTime(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, winrt::Windows::Foundation::DateTime const& value)
    {
        impl::call_factory<XamlBindingHelper, IXamlBindingHelperStatics>([&](IXamlBindingHelperStatics const& f) { return f.SetPropertyFromDateTime(dependencyObject, propertyToSet, value); });
    }
    inline auto XamlBindingHelper::SetPropertyFromDouble(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, double value)
    {
        impl::call_factory<XamlBindingHelper, IXamlBindingHelperStatics>([&](IXamlBindingHelperStatics const& f) { return f.SetPropertyFromDouble(dependencyObject, propertyToSet, value); });
    }
    inline auto XamlBindingHelper::SetPropertyFromInt32(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, int32_t value)
    {
        impl::call_factory<XamlBindingHelper, IXamlBindingHelperStatics>([&](IXamlBindingHelperStatics const& f) { return f.SetPropertyFromInt32(dependencyObject, propertyToSet, value); });
    }
    inline auto XamlBindingHelper::SetPropertyFromUInt32(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, uint32_t value)
    {
        impl::call_factory<XamlBindingHelper, IXamlBindingHelperStatics>([&](IXamlBindingHelperStatics const& f) { return f.SetPropertyFromUInt32(dependencyObject, propertyToSet, value); });
    }
    inline auto XamlBindingHelper::SetPropertyFromInt64(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, int64_t value)
    {
        impl::call_factory<XamlBindingHelper, IXamlBindingHelperStatics>([&](IXamlBindingHelperStatics const& f) { return f.SetPropertyFromInt64(dependencyObject, propertyToSet, value); });
    }
    inline auto XamlBindingHelper::SetPropertyFromUInt64(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, uint64_t value)
    {
        impl::call_factory<XamlBindingHelper, IXamlBindingHelperStatics>([&](IXamlBindingHelperStatics const& f) { return f.SetPropertyFromUInt64(dependencyObject, propertyToSet, value); });
    }
    inline auto XamlBindingHelper::SetPropertyFromSingle(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, float value)
    {
        impl::call_factory<XamlBindingHelper, IXamlBindingHelperStatics>([&](IXamlBindingHelperStatics const& f) { return f.SetPropertyFromSingle(dependencyObject, propertyToSet, value); });
    }
    inline auto XamlBindingHelper::SetPropertyFromPoint(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, winrt::Windows::Foundation::Point const& value)
    {
        impl::call_factory<XamlBindingHelper, IXamlBindingHelperStatics>([&](IXamlBindingHelperStatics const& f) { return f.SetPropertyFromPoint(dependencyObject, propertyToSet, value); });
    }
    inline auto XamlBindingHelper::SetPropertyFromRect(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, winrt::Windows::Foundation::Rect const& value)
    {
        impl::call_factory<XamlBindingHelper, IXamlBindingHelperStatics>([&](IXamlBindingHelperStatics const& f) { return f.SetPropertyFromRect(dependencyObject, propertyToSet, value); });
    }
    inline auto XamlBindingHelper::SetPropertyFromSize(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, winrt::Windows::Foundation::Size const& value)
    {
        impl::call_factory<XamlBindingHelper, IXamlBindingHelperStatics>([&](IXamlBindingHelperStatics const& f) { return f.SetPropertyFromSize(dependencyObject, propertyToSet, value); });
    }
    inline auto XamlBindingHelper::SetPropertyFromTimeSpan(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, winrt::Windows::Foundation::TimeSpan const& value)
    {
        impl::call_factory<XamlBindingHelper, IXamlBindingHelperStatics>([&](IXamlBindingHelperStatics const& f) { return f.SetPropertyFromTimeSpan(dependencyObject, propertyToSet, value); });
    }
    inline auto XamlBindingHelper::SetPropertyFromByte(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, uint8_t value)
    {
        impl::call_factory<XamlBindingHelper, IXamlBindingHelperStatics>([&](IXamlBindingHelperStatics const& f) { return f.SetPropertyFromByte(dependencyObject, propertyToSet, value); });
    }
    inline auto XamlBindingHelper::SetPropertyFromUri(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, winrt::Windows::Foundation::Uri const& value)
    {
        impl::call_factory<XamlBindingHelper, IXamlBindingHelperStatics>([&](IXamlBindingHelperStatics const& f) { return f.SetPropertyFromUri(dependencyObject, propertyToSet, value); });
    }
    inline auto XamlBindingHelper::SetPropertyFromObject(winrt::Windows::Foundation::IInspectable const& dependencyObject, winrt::Windows::UI::Xaml::DependencyProperty const& propertyToSet, winrt::Windows::Foundation::IInspectable const& value)
    {
        impl::call_factory<XamlBindingHelper, IXamlBindingHelperStatics>([&](IXamlBindingHelperStatics const& f) { return f.SetPropertyFromObject(dependencyObject, propertyToSet, value); });
    }
    inline auto XamlMarkupHelper::UnloadObject(winrt::Windows::UI::Xaml::DependencyObject const& element)
    {
        impl::call_factory<XamlMarkupHelper, IXamlMarkupHelperStatics>([&](IXamlMarkupHelperStatics const& f) { return f.UnloadObject(element); });
    }
    inline auto XamlReader::Load(param::hstring const& xaml)
    {
        return impl::call_factory<XamlReader, IXamlReaderStatics>([&](IXamlReaderStatics const& f) { return f.Load(xaml); });
    }
    inline auto XamlReader::LoadWithInitialTemplateValidation(param::hstring const& xaml)
    {
        return impl::call_factory<XamlReader, IXamlReaderStatics>([&](IXamlReaderStatics const& f) { return f.LoadWithInitialTemplateValidation(xaml); });
    }
    template <typename D> WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) IMarkupExtensionOverridesT<D>::ProvideValue() const
    {
        return shim().template try_as<IMarkupExtensionOverrides>().ProvideValue();
    }
    template <typename D, typename... Interfaces>
    struct MarkupExtensionT :
        implements<D, winrt::Windows::UI::Xaml::Markup::IMarkupExtensionOverrides, composing, Interfaces...>,
        impl::require<D, winrt::Windows::UI::Xaml::Markup::IMarkupExtension>,
        impl::base<D, MarkupExtension>,
        winrt::Windows::UI::Xaml::Markup::IMarkupExtensionOverridesT<D>
    {
        using composable = MarkupExtension;
    protected:
        MarkupExtensionT()
        {
            impl::call_factory<MarkupExtension, IMarkupExtensionFactory>([&](IMarkupExtensionFactory const& f) { [[maybe_unused]] auto winrt_impl_discarded = f.CreateInstance(*this, this->m_inner); });
        }
    };
}
namespace std
{
#ifndef WINRT_LEAN_AND_MEAN
    template<> struct hash<winrt::Windows::UI::Xaml::Markup::IComponentConnector> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Markup::IComponentConnector2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Markup::IDataTemplateComponent> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Markup::IMarkupExtension> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Markup::IMarkupExtensionFactory> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Markup::IMarkupExtensionOverrides> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Markup::IXamlBinaryWriter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Markup::IXamlBinaryWriterStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Markup::IXamlBindScopeDiagnostics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Markup::IXamlBindingHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Markup::IXamlBindingHelperStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Markup::IXamlMarkupHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Markup::IXamlMarkupHelperStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Markup::IXamlMember> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Markup::IXamlMetadataProvider> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Markup::IXamlReader> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Markup::IXamlReaderStatics> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Markup::IXamlType> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Markup::IXamlType2> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Markup::MarkupExtension> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Markup::XamlBinaryWriter> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Markup::XamlBindingHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Markup::XamlMarkupHelper> : winrt::impl::hash_base {};
    template<> struct hash<winrt::Windows::UI::Xaml::Markup::XamlReader> : winrt::impl::hash_base {};
#endif
#ifdef __cpp_lib_format
#endif
}
#endif
