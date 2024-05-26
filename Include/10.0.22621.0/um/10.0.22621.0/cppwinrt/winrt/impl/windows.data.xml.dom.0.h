// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Data_Xml_Dom_0_H
#define WINRT_Windows_Data_Xml_Dom_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct IAsyncAction;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
    struct Uri;
}
WINRT_EXPORT namespace winrt::Windows::Storage
{
    struct IStorageFile;
}
WINRT_EXPORT namespace winrt::Windows::Storage::Streams
{
    struct IBuffer;
}
WINRT_EXPORT namespace winrt::Windows::Data::Xml::Dom
{
    enum class NodeType : int32_t
    {
        Invalid = 0,
        ElementNode = 1,
        AttributeNode = 2,
        TextNode = 3,
        DataSectionNode = 4,
        EntityReferenceNode = 5,
        EntityNode = 6,
        ProcessingInstructionNode = 7,
        CommentNode = 8,
        DocumentNode = 9,
        DocumentTypeNode = 10,
        DocumentFragmentNode = 11,
        NotationNode = 12,
    };
    struct IDtdEntity;
    struct IDtdNotation;
    struct IXmlAttribute;
    struct IXmlCDataSection;
    struct IXmlCharacterData;
    struct IXmlComment;
    struct IXmlDocument;
    struct IXmlDocumentFragment;
    struct IXmlDocumentIO;
    struct IXmlDocumentIO2;
    struct IXmlDocumentStatics;
    struct IXmlDocumentType;
    struct IXmlDomImplementation;
    struct IXmlElement;
    struct IXmlEntityReference;
    struct IXmlLoadSettings;
    struct IXmlNamedNodeMap;
    struct IXmlNode;
    struct IXmlNodeList;
    struct IXmlNodeSelector;
    struct IXmlNodeSerializer;
    struct IXmlProcessingInstruction;
    struct IXmlText;
    struct DtdEntity;
    struct DtdNotation;
    struct XmlAttribute;
    struct XmlCDataSection;
    struct XmlComment;
    struct XmlDocument;
    struct XmlDocumentFragment;
    struct XmlDocumentType;
    struct XmlDomImplementation;
    struct XmlElement;
    struct XmlEntityReference;
    struct XmlLoadSettings;
    struct XmlNamedNodeMap;
    struct XmlNodeList;
    struct XmlProcessingInstruction;
    struct XmlText;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Data::Xml::Dom::IDtdEntity>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::IDtdNotation>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::IXmlAttribute>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::IXmlCDataSection>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::IXmlCharacterData>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::IXmlComment>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::IXmlDocument>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::IXmlDocumentFragment>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::IXmlDocumentIO>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::IXmlDocumentIO2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::IXmlDocumentStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::IXmlDocumentType>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::IXmlDomImplementation>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::IXmlElement>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::IXmlEntityReference>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::IXmlLoadSettings>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::IXmlNamedNodeMap>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::IXmlNode>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::IXmlNodeList>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::IXmlNodeSelector>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::IXmlNodeSerializer>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::IXmlProcessingInstruction>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::IXmlText>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::DtdEntity>{ using type = class_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::DtdNotation>{ using type = class_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::XmlAttribute>{ using type = class_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::XmlCDataSection>{ using type = class_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::XmlComment>{ using type = class_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::XmlDocument>{ using type = class_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::XmlDocumentFragment>{ using type = class_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::XmlDocumentType>{ using type = class_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::XmlDomImplementation>{ using type = class_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::XmlElement>{ using type = class_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::XmlEntityReference>{ using type = class_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::XmlLoadSettings>{ using type = class_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::XmlNamedNodeMap>{ using type = class_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::XmlNodeList>{ using type = class_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::XmlProcessingInstruction>{ using type = class_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::XmlText>{ using type = class_category; };
    template <> struct category<winrt::Windows::Data::Xml::Dom::NodeType>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::DtdEntity> = L"Windows.Data.Xml.Dom.DtdEntity";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::DtdNotation> = L"Windows.Data.Xml.Dom.DtdNotation";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::XmlAttribute> = L"Windows.Data.Xml.Dom.XmlAttribute";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::XmlCDataSection> = L"Windows.Data.Xml.Dom.XmlCDataSection";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::XmlComment> = L"Windows.Data.Xml.Dom.XmlComment";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::XmlDocument> = L"Windows.Data.Xml.Dom.XmlDocument";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::XmlDocumentFragment> = L"Windows.Data.Xml.Dom.XmlDocumentFragment";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::XmlDocumentType> = L"Windows.Data.Xml.Dom.XmlDocumentType";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::XmlDomImplementation> = L"Windows.Data.Xml.Dom.XmlDomImplementation";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::XmlElement> = L"Windows.Data.Xml.Dom.XmlElement";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::XmlEntityReference> = L"Windows.Data.Xml.Dom.XmlEntityReference";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::XmlLoadSettings> = L"Windows.Data.Xml.Dom.XmlLoadSettings";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::XmlNamedNodeMap> = L"Windows.Data.Xml.Dom.XmlNamedNodeMap";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::XmlNodeList> = L"Windows.Data.Xml.Dom.XmlNodeList";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::XmlProcessingInstruction> = L"Windows.Data.Xml.Dom.XmlProcessingInstruction";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::XmlText> = L"Windows.Data.Xml.Dom.XmlText";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::NodeType> = L"Windows.Data.Xml.Dom.NodeType";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::IDtdEntity> = L"Windows.Data.Xml.Dom.IDtdEntity";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::IDtdNotation> = L"Windows.Data.Xml.Dom.IDtdNotation";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::IXmlAttribute> = L"Windows.Data.Xml.Dom.IXmlAttribute";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::IXmlCDataSection> = L"Windows.Data.Xml.Dom.IXmlCDataSection";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::IXmlCharacterData> = L"Windows.Data.Xml.Dom.IXmlCharacterData";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::IXmlComment> = L"Windows.Data.Xml.Dom.IXmlComment";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::IXmlDocument> = L"Windows.Data.Xml.Dom.IXmlDocument";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::IXmlDocumentFragment> = L"Windows.Data.Xml.Dom.IXmlDocumentFragment";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::IXmlDocumentIO> = L"Windows.Data.Xml.Dom.IXmlDocumentIO";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::IXmlDocumentIO2> = L"Windows.Data.Xml.Dom.IXmlDocumentIO2";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::IXmlDocumentStatics> = L"Windows.Data.Xml.Dom.IXmlDocumentStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::IXmlDocumentType> = L"Windows.Data.Xml.Dom.IXmlDocumentType";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::IXmlDomImplementation> = L"Windows.Data.Xml.Dom.IXmlDomImplementation";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::IXmlElement> = L"Windows.Data.Xml.Dom.IXmlElement";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::IXmlEntityReference> = L"Windows.Data.Xml.Dom.IXmlEntityReference";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::IXmlLoadSettings> = L"Windows.Data.Xml.Dom.IXmlLoadSettings";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::IXmlNamedNodeMap> = L"Windows.Data.Xml.Dom.IXmlNamedNodeMap";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::IXmlNode> = L"Windows.Data.Xml.Dom.IXmlNode";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::IXmlNodeList> = L"Windows.Data.Xml.Dom.IXmlNodeList";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::IXmlNodeSelector> = L"Windows.Data.Xml.Dom.IXmlNodeSelector";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::IXmlNodeSerializer> = L"Windows.Data.Xml.Dom.IXmlNodeSerializer";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::IXmlProcessingInstruction> = L"Windows.Data.Xml.Dom.IXmlProcessingInstruction";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Xml::Dom::IXmlText> = L"Windows.Data.Xml.Dom.IXmlText";
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Xml::Dom::IDtdEntity>{ 0x6A0B5FFC,0x63B4,0x480F,{ 0x9E,0x6A,0x8A,0x92,0x81,0x6A,0xAD,0xE4 } }; // 6A0B5FFC-63B4-480F-9E6A-8A92816AADE4
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Xml::Dom::IDtdNotation>{ 0x8CB4E04D,0x6D46,0x4EDB,{ 0xAB,0x73,0xDF,0x83,0xC5,0x1A,0xD3,0x97 } }; // 8CB4E04D-6D46-4EDB-AB73-DF83C51AD397
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Xml::Dom::IXmlAttribute>{ 0xAC144AA4,0xB4F1,0x4DB6,{ 0xB2,0x06,0x8A,0x22,0xC3,0x08,0xDB,0x0A } }; // AC144AA4-B4F1-4DB6-B206-8A22C308DB0A
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Xml::Dom::IXmlCDataSection>{ 0x4D04B46F,0xC8BD,0x45B4,{ 0x88,0x99,0x04,0x00,0xD7,0xC2,0xC6,0x0F } }; // 4D04B46F-C8BD-45B4-8899-0400D7C2C60F
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Xml::Dom::IXmlCharacterData>{ 0x132E42AB,0x4E36,0x4DF6,{ 0xB1,0xC8,0x0C,0xE6,0x2F,0xD8,0x8B,0x26 } }; // 132E42AB-4E36-4DF6-B1C8-0CE62FD88B26
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Xml::Dom::IXmlComment>{ 0xBCA474D5,0xB61F,0x4611,{ 0x9C,0xAC,0x2E,0x92,0xE3,0x47,0x6D,0x47 } }; // BCA474D5-B61F-4611-9CAC-2E92E3476D47
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Xml::Dom::IXmlDocument>{ 0xF7F3A506,0x1E87,0x42D6,{ 0xBC,0xFB,0xB8,0xC8,0x09,0xFA,0x54,0x94 } }; // F7F3A506-1E87-42D6-BCFB-B8C809FA5494
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Xml::Dom::IXmlDocumentFragment>{ 0xE2EA6A96,0x0C21,0x44A5,{ 0x8B,0xC9,0x9E,0x4A,0x26,0x27,0x08,0xEC } }; // E2EA6A96-0C21-44A5-8BC9-9E4A262708EC
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Xml::Dom::IXmlDocumentIO>{ 0x6CD0E74E,0xEE65,0x4489,{ 0x9E,0xBF,0xCA,0x43,0xE8,0x7B,0xA6,0x37 } }; // 6CD0E74E-EE65-4489-9EBF-CA43E87BA637
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Xml::Dom::IXmlDocumentIO2>{ 0x5D034661,0x7BD8,0x4AD5,{ 0x9E,0xBF,0x81,0xE6,0x34,0x72,0x63,0xB1 } }; // 5D034661-7BD8-4AD5-9EBF-81E6347263B1
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Xml::Dom::IXmlDocumentStatics>{ 0x5543D254,0xD757,0x4B79,{ 0x95,0x39,0x23,0x2B,0x18,0xF5,0x0B,0xF1 } }; // 5543D254-D757-4B79-9539-232B18F50BF1
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Xml::Dom::IXmlDocumentType>{ 0xF7342425,0x9781,0x4964,{ 0x8E,0x94,0x9B,0x1C,0x6D,0xFC,0x9B,0xC7 } }; // F7342425-9781-4964-8E94-9B1C6DFC9BC7
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Xml::Dom::IXmlDomImplementation>{ 0x6DE58132,0xF11D,0x4FBB,{ 0x8C,0xC6,0x58,0x3C,0xBA,0x93,0x11,0x2F } }; // 6DE58132-F11D-4FBB-8CC6-583CBA93112F
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Xml::Dom::IXmlElement>{ 0x2DFB8A1F,0x6B10,0x4EF8,{ 0x9F,0x83,0xEF,0xCC,0xE8,0xFA,0xEC,0x37 } }; // 2DFB8A1F-6B10-4EF8-9F83-EFCCE8FAEC37
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Xml::Dom::IXmlEntityReference>{ 0x2E2F47BC,0xC3D0,0x4CCF,{ 0xBB,0x86,0x0A,0xB8,0xC3,0x6A,0x61,0xCF } }; // 2E2F47BC-C3D0-4CCF-BB86-0AB8C36A61CF
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Xml::Dom::IXmlLoadSettings>{ 0x58AA07A8,0xFED6,0x46F7,{ 0xB4,0xC5,0xFB,0x1B,0xA7,0x21,0x08,0xD6 } }; // 58AA07A8-FED6-46F7-B4C5-FB1BA72108D6
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Xml::Dom::IXmlNamedNodeMap>{ 0xB3A69EB0,0xAAB0,0x4B82,{ 0xA6,0xFA,0xB1,0x45,0x3F,0x7C,0x02,0x1B } }; // B3A69EB0-AAB0-4B82-A6FA-B1453F7C021B
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Xml::Dom::IXmlNode>{ 0x1C741D59,0x2122,0x47D5,{ 0xA8,0x56,0x83,0xF3,0xD4,0x21,0x48,0x75 } }; // 1C741D59-2122-47D5-A856-83F3D4214875
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Xml::Dom::IXmlNodeList>{ 0x8C60AD77,0x83A4,0x4EC1,{ 0x9C,0x54,0x7B,0xA4,0x29,0xE1,0x3D,0xA6 } }; // 8C60AD77-83A4-4EC1-9C54-7BA429E13DA6
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Xml::Dom::IXmlNodeSelector>{ 0x63DBBA8B,0xD0DB,0x4FE1,{ 0xB7,0x45,0xF9,0x43,0x3A,0xFD,0xC2,0x5B } }; // 63DBBA8B-D0DB-4FE1-B745-F9433AFDC25B
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Xml::Dom::IXmlNodeSerializer>{ 0x5CC5B382,0xE6DD,0x4991,{ 0xAB,0xEF,0x06,0xD8,0xD2,0xE7,0xBD,0x0C } }; // 5CC5B382-E6DD-4991-ABEF-06D8D2E7BD0C
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Xml::Dom::IXmlProcessingInstruction>{ 0x2707FD1E,0x1E92,0x4ECE,{ 0xB6,0xF4,0x26,0xF0,0x69,0x07,0x8D,0xDC } }; // 2707FD1E-1E92-4ECE-B6F4-26F069078DDC
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Xml::Dom::IXmlText>{ 0xF931A4CB,0x308D,0x4760,{ 0xA1,0xD5,0x43,0xB6,0x74,0x50,0xAC,0x7E } }; // F931A4CB-308D-4760-A1D5-43B67450AC7E
    template <> struct default_interface<winrt::Windows::Data::Xml::Dom::DtdEntity>{ using type = winrt::Windows::Data::Xml::Dom::IDtdEntity; };
    template <> struct default_interface<winrt::Windows::Data::Xml::Dom::DtdNotation>{ using type = winrt::Windows::Data::Xml::Dom::IDtdNotation; };
    template <> struct default_interface<winrt::Windows::Data::Xml::Dom::XmlAttribute>{ using type = winrt::Windows::Data::Xml::Dom::IXmlAttribute; };
    template <> struct default_interface<winrt::Windows::Data::Xml::Dom::XmlCDataSection>{ using type = winrt::Windows::Data::Xml::Dom::IXmlCDataSection; };
    template <> struct default_interface<winrt::Windows::Data::Xml::Dom::XmlComment>{ using type = winrt::Windows::Data::Xml::Dom::IXmlComment; };
    template <> struct default_interface<winrt::Windows::Data::Xml::Dom::XmlDocument>{ using type = winrt::Windows::Data::Xml::Dom::IXmlDocument; };
    template <> struct default_interface<winrt::Windows::Data::Xml::Dom::XmlDocumentFragment>{ using type = winrt::Windows::Data::Xml::Dom::IXmlDocumentFragment; };
    template <> struct default_interface<winrt::Windows::Data::Xml::Dom::XmlDocumentType>{ using type = winrt::Windows::Data::Xml::Dom::IXmlDocumentType; };
    template <> struct default_interface<winrt::Windows::Data::Xml::Dom::XmlDomImplementation>{ using type = winrt::Windows::Data::Xml::Dom::IXmlDomImplementation; };
    template <> struct default_interface<winrt::Windows::Data::Xml::Dom::XmlElement>{ using type = winrt::Windows::Data::Xml::Dom::IXmlElement; };
    template <> struct default_interface<winrt::Windows::Data::Xml::Dom::XmlEntityReference>{ using type = winrt::Windows::Data::Xml::Dom::IXmlEntityReference; };
    template <> struct default_interface<winrt::Windows::Data::Xml::Dom::XmlLoadSettings>{ using type = winrt::Windows::Data::Xml::Dom::IXmlLoadSettings; };
    template <> struct default_interface<winrt::Windows::Data::Xml::Dom::XmlNamedNodeMap>{ using type = winrt::Windows::Data::Xml::Dom::IXmlNamedNodeMap; };
    template <> struct default_interface<winrt::Windows::Data::Xml::Dom::XmlNodeList>{ using type = winrt::Windows::Data::Xml::Dom::IXmlNodeList; };
    template <> struct default_interface<winrt::Windows::Data::Xml::Dom::XmlProcessingInstruction>{ using type = winrt::Windows::Data::Xml::Dom::IXmlProcessingInstruction; };
    template <> struct default_interface<winrt::Windows::Data::Xml::Dom::XmlText>{ using type = winrt::Windows::Data::Xml::Dom::IXmlText; };
    template <> struct abi<winrt::Windows::Data::Xml::Dom::IDtdEntity>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PublicId(void**) noexcept = 0;
            virtual int32_t __stdcall get_SystemId(void**) noexcept = 0;
            virtual int32_t __stdcall get_NotationName(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Xml::Dom::IDtdNotation>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PublicId(void**) noexcept = 0;
            virtual int32_t __stdcall get_SystemId(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Xml::Dom::IXmlAttribute>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Name(void**) noexcept = 0;
            virtual int32_t __stdcall get_Specified(bool*) noexcept = 0;
            virtual int32_t __stdcall get_Value(void**) noexcept = 0;
            virtual int32_t __stdcall put_Value(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Xml::Dom::IXmlCDataSection>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::Data::Xml::Dom::IXmlCharacterData>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Data(void**) noexcept = 0;
            virtual int32_t __stdcall put_Data(void*) noexcept = 0;
            virtual int32_t __stdcall get_Length(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall SubstringData(uint32_t, uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall AppendData(void*) noexcept = 0;
            virtual int32_t __stdcall InsertData(uint32_t, void*) noexcept = 0;
            virtual int32_t __stdcall DeleteData(uint32_t, uint32_t) noexcept = 0;
            virtual int32_t __stdcall ReplaceData(uint32_t, uint32_t, void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Xml::Dom::IXmlComment>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::Data::Xml::Dom::IXmlDocument>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Doctype(void**) noexcept = 0;
            virtual int32_t __stdcall get_Implementation(void**) noexcept = 0;
            virtual int32_t __stdcall get_DocumentElement(void**) noexcept = 0;
            virtual int32_t __stdcall CreateElement(void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateDocumentFragment(void**) noexcept = 0;
            virtual int32_t __stdcall CreateTextNode(void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateComment(void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateProcessingInstruction(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateAttribute(void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateEntityReference(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetElementsByTagName(void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateCDataSection(void*, void**) noexcept = 0;
            virtual int32_t __stdcall get_DocumentUri(void**) noexcept = 0;
            virtual int32_t __stdcall CreateAttributeNS(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateElementNS(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetElementById(void*, void**) noexcept = 0;
            virtual int32_t __stdcall ImportNode(void*, bool, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Xml::Dom::IXmlDocumentFragment>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::Data::Xml::Dom::IXmlDocumentIO>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall LoadXml(void*) noexcept = 0;
            virtual int32_t __stdcall LoadXmlWithSettings(void*, void*) noexcept = 0;
            virtual int32_t __stdcall SaveToFileAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Xml::Dom::IXmlDocumentIO2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall LoadXmlFromBuffer(void*) noexcept = 0;
            virtual int32_t __stdcall LoadXmlFromBufferWithSettings(void*, void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Xml::Dom::IXmlDocumentStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall LoadFromUriAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall LoadFromUriWithSettingsAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall LoadFromFileAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall LoadFromFileWithSettingsAsync(void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Xml::Dom::IXmlDocumentType>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Name(void**) noexcept = 0;
            virtual int32_t __stdcall get_Entities(void**) noexcept = 0;
            virtual int32_t __stdcall get_Notations(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Xml::Dom::IXmlDomImplementation>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall HasFeature(void*, void*, bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Xml::Dom::IXmlElement>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_TagName(void**) noexcept = 0;
            virtual int32_t __stdcall GetAttribute(void*, void**) noexcept = 0;
            virtual int32_t __stdcall SetAttribute(void*, void*) noexcept = 0;
            virtual int32_t __stdcall RemoveAttribute(void*) noexcept = 0;
            virtual int32_t __stdcall GetAttributeNode(void*, void**) noexcept = 0;
            virtual int32_t __stdcall SetAttributeNode(void*, void**) noexcept = 0;
            virtual int32_t __stdcall RemoveAttributeNode(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetElementsByTagName(void*, void**) noexcept = 0;
            virtual int32_t __stdcall SetAttributeNS(void*, void*, void*) noexcept = 0;
            virtual int32_t __stdcall GetAttributeNS(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall RemoveAttributeNS(void*, void*) noexcept = 0;
            virtual int32_t __stdcall SetAttributeNodeNS(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetAttributeNodeNS(void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Xml::Dom::IXmlEntityReference>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::Data::Xml::Dom::IXmlLoadSettings>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_MaxElementDepth(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_MaxElementDepth(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_ProhibitDtd(bool*) noexcept = 0;
            virtual int32_t __stdcall put_ProhibitDtd(bool) noexcept = 0;
            virtual int32_t __stdcall get_ResolveExternals(bool*) noexcept = 0;
            virtual int32_t __stdcall put_ResolveExternals(bool) noexcept = 0;
            virtual int32_t __stdcall get_ValidateOnParse(bool*) noexcept = 0;
            virtual int32_t __stdcall put_ValidateOnParse(bool) noexcept = 0;
            virtual int32_t __stdcall get_ElementContentWhiteSpace(bool*) noexcept = 0;
            virtual int32_t __stdcall put_ElementContentWhiteSpace(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Xml::Dom::IXmlNamedNodeMap>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Length(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall Item(uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetNamedItem(void*, void**) noexcept = 0;
            virtual int32_t __stdcall SetNamedItem(void*, void**) noexcept = 0;
            virtual int32_t __stdcall RemoveNamedItem(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetNamedItemNS(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall RemoveNamedItemNS(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall SetNamedItemNS(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Xml::Dom::IXmlNode>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_NodeValue(void**) noexcept = 0;
            virtual int32_t __stdcall put_NodeValue(void*) noexcept = 0;
            virtual int32_t __stdcall get_NodeType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_NodeName(void**) noexcept = 0;
            virtual int32_t __stdcall get_ParentNode(void**) noexcept = 0;
            virtual int32_t __stdcall get_ChildNodes(void**) noexcept = 0;
            virtual int32_t __stdcall get_FirstChild(void**) noexcept = 0;
            virtual int32_t __stdcall get_LastChild(void**) noexcept = 0;
            virtual int32_t __stdcall get_PreviousSibling(void**) noexcept = 0;
            virtual int32_t __stdcall get_NextSibling(void**) noexcept = 0;
            virtual int32_t __stdcall get_Attributes(void**) noexcept = 0;
            virtual int32_t __stdcall HasChildNodes(bool*) noexcept = 0;
            virtual int32_t __stdcall get_OwnerDocument(void**) noexcept = 0;
            virtual int32_t __stdcall InsertBefore(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall ReplaceChild(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall RemoveChild(void*, void**) noexcept = 0;
            virtual int32_t __stdcall AppendChild(void*, void**) noexcept = 0;
            virtual int32_t __stdcall CloneNode(bool, void**) noexcept = 0;
            virtual int32_t __stdcall get_NamespaceUri(void**) noexcept = 0;
            virtual int32_t __stdcall get_LocalName(void**) noexcept = 0;
            virtual int32_t __stdcall get_Prefix(void**) noexcept = 0;
            virtual int32_t __stdcall Normalize() noexcept = 0;
            virtual int32_t __stdcall put_Prefix(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Xml::Dom::IXmlNodeList>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Length(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall Item(uint32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Xml::Dom::IXmlNodeSelector>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall SelectSingleNode(void*, void**) noexcept = 0;
            virtual int32_t __stdcall SelectNodes(void*, void**) noexcept = 0;
            virtual int32_t __stdcall SelectSingleNodeNS(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall SelectNodesNS(void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Xml::Dom::IXmlNodeSerializer>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetXml(void**) noexcept = 0;
            virtual int32_t __stdcall get_InnerText(void**) noexcept = 0;
            virtual int32_t __stdcall put_InnerText(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Xml::Dom::IXmlProcessingInstruction>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Target(void**) noexcept = 0;
            virtual int32_t __stdcall get_Data(void**) noexcept = 0;
            virtual int32_t __stdcall put_Data(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Xml::Dom::IXmlText>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall SplitText(uint32_t, void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Data_Xml_Dom_IDtdEntity
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) PublicId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) SystemId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) NotationName() const;
    };
    template <> struct consume<winrt::Windows::Data::Xml::Dom::IDtdEntity>
    {
        template <typename D> using type = consume_Windows_Data_Xml_Dom_IDtdEntity<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Xml_Dom_IDtdNotation
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) PublicId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) SystemId() const;
    };
    template <> struct consume<winrt::Windows::Data::Xml::Dom::IDtdNotation>
    {
        template <typename D> using type = consume_Windows_Data_Xml_Dom_IDtdNotation<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Xml_Dom_IXmlAttribute
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Name() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) Specified() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Value() const;
        WINRT_IMPL_AUTO(void) Value(param::hstring const& value) const;
    };
    template <> struct consume<winrt::Windows::Data::Xml::Dom::IXmlAttribute>
    {
        template <typename D> using type = consume_Windows_Data_Xml_Dom_IXmlAttribute<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Xml_Dom_IXmlCDataSection
    {
    };
    template <> struct consume<winrt::Windows::Data::Xml::Dom::IXmlCDataSection>
    {
        template <typename D> using type = consume_Windows_Data_Xml_Dom_IXmlCDataSection<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Xml_Dom_IXmlCharacterData
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Data() const;
        WINRT_IMPL_AUTO(void) Data(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Length() const;
        WINRT_IMPL_AUTO(hstring) SubstringData(uint32_t offset, uint32_t count) const;
        WINRT_IMPL_AUTO(void) AppendData(param::hstring const& data) const;
        WINRT_IMPL_AUTO(void) InsertData(uint32_t offset, param::hstring const& data) const;
        WINRT_IMPL_AUTO(void) DeleteData(uint32_t offset, uint32_t count) const;
        WINRT_IMPL_AUTO(void) ReplaceData(uint32_t offset, uint32_t count, param::hstring const& data) const;
    };
    template <> struct consume<winrt::Windows::Data::Xml::Dom::IXmlCharacterData>
    {
        template <typename D> using type = consume_Windows_Data_Xml_Dom_IXmlCharacterData<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Xml_Dom_IXmlComment
    {
    };
    template <> struct consume<winrt::Windows::Data::Xml::Dom::IXmlComment>
    {
        template <typename D> using type = consume_Windows_Data_Xml_Dom_IXmlComment<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Xml_Dom_IXmlDocument
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlDocumentType) Doctype() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlDomImplementation) Implementation() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlElement) DocumentElement() const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlElement) CreateElement(param::hstring const& tagName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlDocumentFragment) CreateDocumentFragment() const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlText) CreateTextNode(param::hstring const& data) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlComment) CreateComment(param::hstring const& data) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlProcessingInstruction) CreateProcessingInstruction(param::hstring const& target, param::hstring const& data) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlAttribute) CreateAttribute(param::hstring const& name) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlEntityReference) CreateEntityReference(param::hstring const& name) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlNodeList) GetElementsByTagName(param::hstring const& tagName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlCDataSection) CreateCDataSection(param::hstring const& data) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DocumentUri() const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlAttribute) CreateAttributeNS(winrt::Windows::Foundation::IInspectable const& namespaceUri, param::hstring const& qualifiedName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlElement) CreateElementNS(winrt::Windows::Foundation::IInspectable const& namespaceUri, param::hstring const& qualifiedName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlElement) GetElementById(param::hstring const& elementId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlNode) ImportNode(winrt::Windows::Data::Xml::Dom::IXmlNode const& node, bool deep) const;
    };
    template <> struct consume<winrt::Windows::Data::Xml::Dom::IXmlDocument>
    {
        template <typename D> using type = consume_Windows_Data_Xml_Dom_IXmlDocument<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Xml_Dom_IXmlDocumentFragment
    {
    };
    template <> struct consume<winrt::Windows::Data::Xml::Dom::IXmlDocumentFragment>
    {
        template <typename D> using type = consume_Windows_Data_Xml_Dom_IXmlDocumentFragment<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Xml_Dom_IXmlDocumentIO
    {
        WINRT_IMPL_AUTO(void) LoadXml(param::hstring const& xml) const;
        WINRT_IMPL_AUTO(void) LoadXml(param::hstring const& xml, winrt::Windows::Data::Xml::Dom::XmlLoadSettings const& loadSettings) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) SaveToFileAsync(winrt::Windows::Storage::IStorageFile const& file) const;
    };
    template <> struct consume<winrt::Windows::Data::Xml::Dom::IXmlDocumentIO>
    {
        template <typename D> using type = consume_Windows_Data_Xml_Dom_IXmlDocumentIO<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Xml_Dom_IXmlDocumentIO2
    {
        WINRT_IMPL_AUTO(void) LoadXmlFromBuffer(winrt::Windows::Storage::Streams::IBuffer const& buffer) const;
        WINRT_IMPL_AUTO(void) LoadXmlFromBuffer(winrt::Windows::Storage::Streams::IBuffer const& buffer, winrt::Windows::Data::Xml::Dom::XmlLoadSettings const& loadSettings) const;
    };
    template <> struct consume<winrt::Windows::Data::Xml::Dom::IXmlDocumentIO2>
    {
        template <typename D> using type = consume_Windows_Data_Xml_Dom_IXmlDocumentIO2<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Xml_Dom_IXmlDocumentStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Data::Xml::Dom::XmlDocument>) LoadFromUriAsync(winrt::Windows::Foundation::Uri const& uri) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Data::Xml::Dom::XmlDocument>) LoadFromUriAsync(winrt::Windows::Foundation::Uri const& uri, winrt::Windows::Data::Xml::Dom::XmlLoadSettings const& loadSettings) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Data::Xml::Dom::XmlDocument>) LoadFromFileAsync(winrt::Windows::Storage::IStorageFile const& file) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Data::Xml::Dom::XmlDocument>) LoadFromFileAsync(winrt::Windows::Storage::IStorageFile const& file, winrt::Windows::Data::Xml::Dom::XmlLoadSettings const& loadSettings) const;
    };
    template <> struct consume<winrt::Windows::Data::Xml::Dom::IXmlDocumentStatics>
    {
        template <typename D> using type = consume_Windows_Data_Xml_Dom_IXmlDocumentStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Xml_Dom_IXmlDocumentType
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Name() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlNamedNodeMap) Entities() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlNamedNodeMap) Notations() const;
    };
    template <> struct consume<winrt::Windows::Data::Xml::Dom::IXmlDocumentType>
    {
        template <typename D> using type = consume_Windows_Data_Xml_Dom_IXmlDocumentType<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Xml_Dom_IXmlDomImplementation
    {
        WINRT_IMPL_AUTO(bool) HasFeature(param::hstring const& feature, winrt::Windows::Foundation::IInspectable const& version) const;
    };
    template <> struct consume<winrt::Windows::Data::Xml::Dom::IXmlDomImplementation>
    {
        template <typename D> using type = consume_Windows_Data_Xml_Dom_IXmlDomImplementation<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Xml_Dom_IXmlElement
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) TagName() const;
        WINRT_IMPL_AUTO(hstring) GetAttribute(param::hstring const& attributeName) const;
        WINRT_IMPL_AUTO(void) SetAttribute(param::hstring const& attributeName, param::hstring const& attributeValue) const;
        WINRT_IMPL_AUTO(void) RemoveAttribute(param::hstring const& attributeName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlAttribute) GetAttributeNode(param::hstring const& attributeName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlAttribute) SetAttributeNode(winrt::Windows::Data::Xml::Dom::XmlAttribute const& newAttribute) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlAttribute) RemoveAttributeNode(winrt::Windows::Data::Xml::Dom::XmlAttribute const& attributeNode) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlNodeList) GetElementsByTagName(param::hstring const& tagName) const;
        WINRT_IMPL_AUTO(void) SetAttributeNS(winrt::Windows::Foundation::IInspectable const& namespaceUri, param::hstring const& qualifiedName, param::hstring const& value) const;
        WINRT_IMPL_AUTO(hstring) GetAttributeNS(winrt::Windows::Foundation::IInspectable const& namespaceUri, param::hstring const& localName) const;
        WINRT_IMPL_AUTO(void) RemoveAttributeNS(winrt::Windows::Foundation::IInspectable const& namespaceUri, param::hstring const& localName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlAttribute) SetAttributeNodeNS(winrt::Windows::Data::Xml::Dom::XmlAttribute const& newAttribute) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlAttribute) GetAttributeNodeNS(winrt::Windows::Foundation::IInspectable const& namespaceUri, param::hstring const& localName) const;
    };
    template <> struct consume<winrt::Windows::Data::Xml::Dom::IXmlElement>
    {
        template <typename D> using type = consume_Windows_Data_Xml_Dom_IXmlElement<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Xml_Dom_IXmlEntityReference
    {
    };
    template <> struct consume<winrt::Windows::Data::Xml::Dom::IXmlEntityReference>
    {
        template <typename D> using type = consume_Windows_Data_Xml_Dom_IXmlEntityReference<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Xml_Dom_IXmlLoadSettings
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MaxElementDepth() const;
        WINRT_IMPL_AUTO(void) MaxElementDepth(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ProhibitDtd() const;
        WINRT_IMPL_AUTO(void) ProhibitDtd(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ResolveExternals() const;
        WINRT_IMPL_AUTO(void) ResolveExternals(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ValidateOnParse() const;
        WINRT_IMPL_AUTO(void) ValidateOnParse(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ElementContentWhiteSpace() const;
        WINRT_IMPL_AUTO(void) ElementContentWhiteSpace(bool value) const;
    };
    template <> struct consume<winrt::Windows::Data::Xml::Dom::IXmlLoadSettings>
    {
        template <typename D> using type = consume_Windows_Data_Xml_Dom_IXmlLoadSettings<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Xml_Dom_IXmlNamedNodeMap
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Length() const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlNode) Item(uint32_t index) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlNode) GetNamedItem(param::hstring const& name) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlNode) SetNamedItem(winrt::Windows::Data::Xml::Dom::IXmlNode const& node) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlNode) RemoveNamedItem(param::hstring const& name) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlNode) GetNamedItemNS(winrt::Windows::Foundation::IInspectable const& namespaceUri, param::hstring const& name) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlNode) RemoveNamedItemNS(winrt::Windows::Foundation::IInspectable const& namespaceUri, param::hstring const& name) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlNode) SetNamedItemNS(winrt::Windows::Data::Xml::Dom::IXmlNode const& node) const;
    };
    template <> struct consume<winrt::Windows::Data::Xml::Dom::IXmlNamedNodeMap>
    {
        template <typename D> using type = consume_Windows_Data_Xml_Dom_IXmlNamedNodeMap<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Xml_Dom_IXmlNode
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) NodeValue() const;
        WINRT_IMPL_AUTO(void) NodeValue(winrt::Windows::Foundation::IInspectable const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::NodeType) NodeType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) NodeName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlNode) ParentNode() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlNodeList) ChildNodes() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlNode) FirstChild() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlNode) LastChild() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlNode) PreviousSibling() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlNode) NextSibling() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlNamedNodeMap) Attributes() const;
        WINRT_IMPL_AUTO(bool) HasChildNodes() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlDocument) OwnerDocument() const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlNode) InsertBefore(winrt::Windows::Data::Xml::Dom::IXmlNode const& newChild, winrt::Windows::Data::Xml::Dom::IXmlNode const& referenceChild) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlNode) ReplaceChild(winrt::Windows::Data::Xml::Dom::IXmlNode const& newChild, winrt::Windows::Data::Xml::Dom::IXmlNode const& referenceChild) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlNode) RemoveChild(winrt::Windows::Data::Xml::Dom::IXmlNode const& childNode) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlNode) AppendChild(winrt::Windows::Data::Xml::Dom::IXmlNode const& newChild) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlNode) CloneNode(bool deep) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) NamespaceUri() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) LocalName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) Prefix() const;
        WINRT_IMPL_AUTO(void) Normalize() const;
        WINRT_IMPL_AUTO(void) Prefix(winrt::Windows::Foundation::IInspectable const& value) const;
    };
    template <> struct consume<winrt::Windows::Data::Xml::Dom::IXmlNode>
    {
        template <typename D> using type = consume_Windows_Data_Xml_Dom_IXmlNode<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Xml_Dom_IXmlNodeList
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Length() const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlNode) Item(uint32_t index) const;
    };
    template <> struct consume<winrt::Windows::Data::Xml::Dom::IXmlNodeList>
    {
        template <typename D> using type = consume_Windows_Data_Xml_Dom_IXmlNodeList<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Xml_Dom_IXmlNodeSelector
    {
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlNode) SelectSingleNode(param::hstring const& xpath) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlNodeList) SelectNodes(param::hstring const& xpath) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlNode) SelectSingleNodeNS(param::hstring const& xpath, winrt::Windows::Foundation::IInspectable const& namespaces) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::XmlNodeList) SelectNodesNS(param::hstring const& xpath, winrt::Windows::Foundation::IInspectable const& namespaces) const;
    };
    template <> struct consume<winrt::Windows::Data::Xml::Dom::IXmlNodeSelector>
    {
        template <typename D> using type = consume_Windows_Data_Xml_Dom_IXmlNodeSelector<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Xml_Dom_IXmlNodeSerializer
    {
        WINRT_IMPL_AUTO(hstring) GetXml() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) InnerText() const;
        WINRT_IMPL_AUTO(void) InnerText(param::hstring const& value) const;
    };
    template <> struct consume<winrt::Windows::Data::Xml::Dom::IXmlNodeSerializer>
    {
        template <typename D> using type = consume_Windows_Data_Xml_Dom_IXmlNodeSerializer<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Xml_Dom_IXmlProcessingInstruction
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Target() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Data() const;
        WINRT_IMPL_AUTO(void) Data(param::hstring const& value) const;
    };
    template <> struct consume<winrt::Windows::Data::Xml::Dom::IXmlProcessingInstruction>
    {
        template <typename D> using type = consume_Windows_Data_Xml_Dom_IXmlProcessingInstruction<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Xml_Dom_IXmlText
    {
        WINRT_IMPL_AUTO(winrt::Windows::Data::Xml::Dom::IXmlText) SplitText(uint32_t offset) const;
    };
    template <> struct consume<winrt::Windows::Data::Xml::Dom::IXmlText>
    {
        template <typename D> using type = consume_Windows_Data_Xml_Dom_IXmlText<D>;
    };
}
#endif
