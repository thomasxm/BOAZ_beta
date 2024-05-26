// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Data_Xml_Dom_1_H
#define WINRT_Windows_Data_Xml_Dom_1_H
#include "winrt/impl/Windows.Foundation.Collections.0.h"
#include "winrt/impl/Windows.Data.Xml.Dom.0.h"
WINRT_EXPORT namespace winrt::Windows::Data::Xml::Dom
{
    struct __declspec(empty_bases) IDtdEntity :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDtdEntity>,
        impl::require<winrt::Windows::Data::Xml::Dom::IDtdEntity, winrt::Windows::Data::Xml::Dom::IXmlNodeSelector, winrt::Windows::Data::Xml::Dom::IXmlNodeSerializer, winrt::Windows::Data::Xml::Dom::IXmlNode>
    {
        IDtdEntity(std::nullptr_t = nullptr) noexcept {}
        IDtdEntity(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IDtdNotation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IDtdNotation>,
        impl::require<winrt::Windows::Data::Xml::Dom::IDtdNotation, winrt::Windows::Data::Xml::Dom::IXmlNodeSelector, winrt::Windows::Data::Xml::Dom::IXmlNodeSerializer, winrt::Windows::Data::Xml::Dom::IXmlNode>
    {
        IDtdNotation(std::nullptr_t = nullptr) noexcept {}
        IDtdNotation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IXmlAttribute :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IXmlAttribute>,
        impl::require<winrt::Windows::Data::Xml::Dom::IXmlAttribute, winrt::Windows::Data::Xml::Dom::IXmlNodeSelector, winrt::Windows::Data::Xml::Dom::IXmlNodeSerializer, winrt::Windows::Data::Xml::Dom::IXmlNode>
    {
        IXmlAttribute(std::nullptr_t = nullptr) noexcept {}
        IXmlAttribute(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IXmlCDataSection :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IXmlCDataSection>,
        impl::require<winrt::Windows::Data::Xml::Dom::IXmlCDataSection, winrt::Windows::Data::Xml::Dom::IXmlNodeSelector, winrt::Windows::Data::Xml::Dom::IXmlNodeSerializer, winrt::Windows::Data::Xml::Dom::IXmlNode, winrt::Windows::Data::Xml::Dom::IXmlCharacterData, winrt::Windows::Data::Xml::Dom::IXmlText>
    {
        IXmlCDataSection(std::nullptr_t = nullptr) noexcept {}
        IXmlCDataSection(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IXmlCharacterData :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IXmlCharacterData>,
        impl::require<winrt::Windows::Data::Xml::Dom::IXmlCharacterData, winrt::Windows::Data::Xml::Dom::IXmlNodeSelector, winrt::Windows::Data::Xml::Dom::IXmlNodeSerializer, winrt::Windows::Data::Xml::Dom::IXmlNode>
    {
        IXmlCharacterData(std::nullptr_t = nullptr) noexcept {}
        IXmlCharacterData(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IXmlComment :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IXmlComment>,
        impl::require<winrt::Windows::Data::Xml::Dom::IXmlComment, winrt::Windows::Data::Xml::Dom::IXmlNodeSelector, winrt::Windows::Data::Xml::Dom::IXmlNodeSerializer, winrt::Windows::Data::Xml::Dom::IXmlNode, winrt::Windows::Data::Xml::Dom::IXmlCharacterData>
    {
        IXmlComment(std::nullptr_t = nullptr) noexcept {}
        IXmlComment(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IXmlDocument :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IXmlDocument>,
        impl::require<winrt::Windows::Data::Xml::Dom::IXmlDocument, winrt::Windows::Data::Xml::Dom::IXmlNodeSelector, winrt::Windows::Data::Xml::Dom::IXmlNodeSerializer, winrt::Windows::Data::Xml::Dom::IXmlNode>
    {
        IXmlDocument(std::nullptr_t = nullptr) noexcept {}
        IXmlDocument(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IXmlDocumentFragment :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IXmlDocumentFragment>,
        impl::require<winrt::Windows::Data::Xml::Dom::IXmlDocumentFragment, winrt::Windows::Data::Xml::Dom::IXmlNodeSelector, winrt::Windows::Data::Xml::Dom::IXmlNodeSerializer, winrt::Windows::Data::Xml::Dom::IXmlNode>
    {
        IXmlDocumentFragment(std::nullptr_t = nullptr) noexcept {}
        IXmlDocumentFragment(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IXmlDocumentIO :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IXmlDocumentIO>
    {
        IXmlDocumentIO(std::nullptr_t = nullptr) noexcept {}
        IXmlDocumentIO(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IXmlDocumentIO2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IXmlDocumentIO2>
    {
        IXmlDocumentIO2(std::nullptr_t = nullptr) noexcept {}
        IXmlDocumentIO2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IXmlDocumentStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IXmlDocumentStatics>
    {
        IXmlDocumentStatics(std::nullptr_t = nullptr) noexcept {}
        IXmlDocumentStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IXmlDocumentType :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IXmlDocumentType>,
        impl::require<winrt::Windows::Data::Xml::Dom::IXmlDocumentType, winrt::Windows::Data::Xml::Dom::IXmlNodeSelector, winrt::Windows::Data::Xml::Dom::IXmlNodeSerializer, winrt::Windows::Data::Xml::Dom::IXmlNode>
    {
        IXmlDocumentType(std::nullptr_t = nullptr) noexcept {}
        IXmlDocumentType(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IXmlDomImplementation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IXmlDomImplementation>
    {
        IXmlDomImplementation(std::nullptr_t = nullptr) noexcept {}
        IXmlDomImplementation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IXmlElement :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IXmlElement>,
        impl::require<winrt::Windows::Data::Xml::Dom::IXmlElement, winrt::Windows::Data::Xml::Dom::IXmlNodeSelector, winrt::Windows::Data::Xml::Dom::IXmlNodeSerializer, winrt::Windows::Data::Xml::Dom::IXmlNode>
    {
        IXmlElement(std::nullptr_t = nullptr) noexcept {}
        IXmlElement(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IXmlEntityReference :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IXmlEntityReference>,
        impl::require<winrt::Windows::Data::Xml::Dom::IXmlEntityReference, winrt::Windows::Data::Xml::Dom::IXmlNodeSelector, winrt::Windows::Data::Xml::Dom::IXmlNodeSerializer, winrt::Windows::Data::Xml::Dom::IXmlNode>
    {
        IXmlEntityReference(std::nullptr_t = nullptr) noexcept {}
        IXmlEntityReference(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IXmlLoadSettings :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IXmlLoadSettings>
    {
        IXmlLoadSettings(std::nullptr_t = nullptr) noexcept {}
        IXmlLoadSettings(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IXmlNamedNodeMap :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IXmlNamedNodeMap>,
        impl::require<winrt::Windows::Data::Xml::Dom::IXmlNamedNodeMap, winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Data::Xml::Dom::IXmlNode>, winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Data::Xml::Dom::IXmlNode>>
    {
        IXmlNamedNodeMap(std::nullptr_t = nullptr) noexcept {}
        IXmlNamedNodeMap(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IXmlNode :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IXmlNode>,
        impl::require<winrt::Windows::Data::Xml::Dom::IXmlNode, winrt::Windows::Data::Xml::Dom::IXmlNodeSelector, winrt::Windows::Data::Xml::Dom::IXmlNodeSerializer>
    {
        IXmlNode(std::nullptr_t = nullptr) noexcept {}
        IXmlNode(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IXmlNodeList :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IXmlNodeList>,
        impl::require<winrt::Windows::Data::Xml::Dom::IXmlNodeList, winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Data::Xml::Dom::IXmlNode>, winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Data::Xml::Dom::IXmlNode>>
    {
        IXmlNodeList(std::nullptr_t = nullptr) noexcept {}
        IXmlNodeList(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IXmlNodeSelector :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IXmlNodeSelector>
    {
        IXmlNodeSelector(std::nullptr_t = nullptr) noexcept {}
        IXmlNodeSelector(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IXmlNodeSerializer :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IXmlNodeSerializer>
    {
        IXmlNodeSerializer(std::nullptr_t = nullptr) noexcept {}
        IXmlNodeSerializer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IXmlProcessingInstruction :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IXmlProcessingInstruction>,
        impl::require<winrt::Windows::Data::Xml::Dom::IXmlProcessingInstruction, winrt::Windows::Data::Xml::Dom::IXmlNodeSelector, winrt::Windows::Data::Xml::Dom::IXmlNodeSerializer, winrt::Windows::Data::Xml::Dom::IXmlNode>
    {
        IXmlProcessingInstruction(std::nullptr_t = nullptr) noexcept {}
        IXmlProcessingInstruction(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IXmlText :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IXmlText>,
        impl::require<winrt::Windows::Data::Xml::Dom::IXmlText, winrt::Windows::Data::Xml::Dom::IXmlNodeSelector, winrt::Windows::Data::Xml::Dom::IXmlNodeSerializer, winrt::Windows::Data::Xml::Dom::IXmlNode, winrt::Windows::Data::Xml::Dom::IXmlCharacterData>
    {
        IXmlText(std::nullptr_t = nullptr) noexcept {}
        IXmlText(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
