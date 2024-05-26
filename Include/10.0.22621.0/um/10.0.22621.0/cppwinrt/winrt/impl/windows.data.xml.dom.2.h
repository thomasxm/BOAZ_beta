// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Data_Xml_Dom_2_H
#define WINRT_Windows_Data_Xml_Dom_2_H
#include "winrt/impl/Windows.Foundation.1.h"
#include "winrt/impl/Windows.Foundation.Collections.1.h"
#include "winrt/impl/Windows.Storage.1.h"
#include "winrt/impl/Windows.Data.Xml.Dom.1.h"
WINRT_EXPORT namespace winrt::Windows::Data::Xml::Dom
{
    struct __declspec(empty_bases) DtdEntity : winrt::Windows::Data::Xml::Dom::IDtdEntity
    {
        DtdEntity(std::nullptr_t) noexcept {}
        DtdEntity(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Data::Xml::Dom::IDtdEntity(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) DtdNotation : winrt::Windows::Data::Xml::Dom::IDtdNotation
    {
        DtdNotation(std::nullptr_t) noexcept {}
        DtdNotation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Data::Xml::Dom::IDtdNotation(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) XmlAttribute : winrt::Windows::Data::Xml::Dom::IXmlAttribute
    {
        XmlAttribute(std::nullptr_t) noexcept {}
        XmlAttribute(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Data::Xml::Dom::IXmlAttribute(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) XmlCDataSection : winrt::Windows::Data::Xml::Dom::IXmlCDataSection
    {
        XmlCDataSection(std::nullptr_t) noexcept {}
        XmlCDataSection(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Data::Xml::Dom::IXmlCDataSection(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) XmlComment : winrt::Windows::Data::Xml::Dom::IXmlComment
    {
        XmlComment(std::nullptr_t) noexcept {}
        XmlComment(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Data::Xml::Dom::IXmlComment(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) XmlDocument : winrt::Windows::Data::Xml::Dom::IXmlDocument,
        impl::require<XmlDocument, winrt::Windows::Data::Xml::Dom::IXmlDocumentIO, winrt::Windows::Data::Xml::Dom::IXmlDocumentIO2>
    {
        XmlDocument(std::nullptr_t) noexcept {}
        XmlDocument(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Data::Xml::Dom::IXmlDocument(ptr, take_ownership_from_abi) {}
        XmlDocument();
        static auto LoadFromUriAsync(winrt::Windows::Foundation::Uri const& uri);
        static auto LoadFromUriAsync(winrt::Windows::Foundation::Uri const& uri, winrt::Windows::Data::Xml::Dom::XmlLoadSettings const& loadSettings);
        static auto LoadFromFileAsync(winrt::Windows::Storage::IStorageFile const& file);
        static auto LoadFromFileAsync(winrt::Windows::Storage::IStorageFile const& file, winrt::Windows::Data::Xml::Dom::XmlLoadSettings const& loadSettings);
    };
    struct __declspec(empty_bases) XmlDocumentFragment : winrt::Windows::Data::Xml::Dom::IXmlDocumentFragment
    {
        XmlDocumentFragment(std::nullptr_t) noexcept {}
        XmlDocumentFragment(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Data::Xml::Dom::IXmlDocumentFragment(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) XmlDocumentType : winrt::Windows::Data::Xml::Dom::IXmlDocumentType
    {
        XmlDocumentType(std::nullptr_t) noexcept {}
        XmlDocumentType(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Data::Xml::Dom::IXmlDocumentType(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) XmlDomImplementation : winrt::Windows::Data::Xml::Dom::IXmlDomImplementation
    {
        XmlDomImplementation(std::nullptr_t) noexcept {}
        XmlDomImplementation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Data::Xml::Dom::IXmlDomImplementation(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) XmlElement : winrt::Windows::Data::Xml::Dom::IXmlElement
    {
        XmlElement(std::nullptr_t) noexcept {}
        XmlElement(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Data::Xml::Dom::IXmlElement(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) XmlEntityReference : winrt::Windows::Data::Xml::Dom::IXmlEntityReference
    {
        XmlEntityReference(std::nullptr_t) noexcept {}
        XmlEntityReference(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Data::Xml::Dom::IXmlEntityReference(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) XmlLoadSettings : winrt::Windows::Data::Xml::Dom::IXmlLoadSettings
    {
        XmlLoadSettings(std::nullptr_t) noexcept {}
        XmlLoadSettings(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Data::Xml::Dom::IXmlLoadSettings(ptr, take_ownership_from_abi) {}
        XmlLoadSettings();
    };
    struct __declspec(empty_bases) XmlNamedNodeMap : winrt::Windows::Data::Xml::Dom::IXmlNamedNodeMap
    {
        XmlNamedNodeMap(std::nullptr_t) noexcept {}
        XmlNamedNodeMap(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Data::Xml::Dom::IXmlNamedNodeMap(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) XmlNodeList : winrt::Windows::Data::Xml::Dom::IXmlNodeList
    {
        XmlNodeList(std::nullptr_t) noexcept {}
        XmlNodeList(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Data::Xml::Dom::IXmlNodeList(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) XmlProcessingInstruction : winrt::Windows::Data::Xml::Dom::IXmlProcessingInstruction
    {
        XmlProcessingInstruction(std::nullptr_t) noexcept {}
        XmlProcessingInstruction(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Data::Xml::Dom::IXmlProcessingInstruction(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) XmlText : winrt::Windows::Data::Xml::Dom::IXmlText
    {
        XmlText(std::nullptr_t) noexcept {}
        XmlText(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Data::Xml::Dom::IXmlText(ptr, take_ownership_from_abi) {}
    };
}
#endif
