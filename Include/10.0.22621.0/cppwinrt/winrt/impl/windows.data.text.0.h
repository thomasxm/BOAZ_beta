// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Data_Text_0_H
#define WINRT_Windows_Data_Text_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IIterable;
    template <typename T> struct __declspec(empty_bases) IVectorView;
}
WINRT_EXPORT namespace winrt::Windows::UI::Text::Core
{
    enum class CoreTextInputScope : int32_t;
}
WINRT_EXPORT namespace winrt::Windows::Data::Text
{
    enum class AlternateNormalizationFormat : int32_t
    {
        NotNormalized = 0,
        Number = 1,
        Currency = 3,
        Date = 4,
        Time = 5,
    };
    enum class TextPredictionOptions : uint32_t
    {
        None = 0,
        Predictions = 0x1,
        Corrections = 0x2,
    };
    enum class UnicodeGeneralCategory : int32_t
    {
        UppercaseLetter = 0,
        LowercaseLetter = 1,
        TitlecaseLetter = 2,
        ModifierLetter = 3,
        OtherLetter = 4,
        NonspacingMark = 5,
        SpacingCombiningMark = 6,
        EnclosingMark = 7,
        DecimalDigitNumber = 8,
        LetterNumber = 9,
        OtherNumber = 10,
        SpaceSeparator = 11,
        LineSeparator = 12,
        ParagraphSeparator = 13,
        Control = 14,
        Format = 15,
        Surrogate = 16,
        PrivateUse = 17,
        ConnectorPunctuation = 18,
        DashPunctuation = 19,
        OpenPunctuation = 20,
        ClosePunctuation = 21,
        InitialQuotePunctuation = 22,
        FinalQuotePunctuation = 23,
        OtherPunctuation = 24,
        MathSymbol = 25,
        CurrencySymbol = 26,
        ModifierSymbol = 27,
        OtherSymbol = 28,
        NotAssigned = 29,
    };
    enum class UnicodeNumericType : int32_t
    {
        None = 0,
        Decimal = 1,
        Digit = 2,
        Numeric = 3,
    };
    struct IAlternateWordForm;
    struct ISelectableWordSegment;
    struct ISelectableWordsSegmenter;
    struct ISelectableWordsSegmenterFactory;
    struct ISemanticTextQuery;
    struct ISemanticTextQueryFactory;
    struct ITextConversionGenerator;
    struct ITextConversionGeneratorFactory;
    struct ITextPhoneme;
    struct ITextPredictionGenerator;
    struct ITextPredictionGenerator2;
    struct ITextPredictionGeneratorFactory;
    struct ITextReverseConversionGenerator;
    struct ITextReverseConversionGenerator2;
    struct ITextReverseConversionGeneratorFactory;
    struct IUnicodeCharactersStatics;
    struct IWordSegment;
    struct IWordsSegmenter;
    struct IWordsSegmenterFactory;
    struct AlternateWordForm;
    struct SelectableWordSegment;
    struct SelectableWordsSegmenter;
    struct SemanticTextQuery;
    struct TextConversionGenerator;
    struct TextPhoneme;
    struct TextPredictionGenerator;
    struct TextReverseConversionGenerator;
    struct UnicodeCharacters;
    struct WordSegment;
    struct WordsSegmenter;
    struct TextSegment;
    struct SelectableWordSegmentsTokenizingHandler;
    struct WordSegmentsTokenizingHandler;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Data::Text::IAlternateWordForm>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Text::ISelectableWordSegment>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Text::ISelectableWordsSegmenter>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Text::ISelectableWordsSegmenterFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Text::ISemanticTextQuery>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Text::ISemanticTextQueryFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Text::ITextConversionGenerator>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Text::ITextConversionGeneratorFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Text::ITextPhoneme>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Text::ITextPredictionGenerator>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Text::ITextPredictionGenerator2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Text::ITextPredictionGeneratorFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Text::ITextReverseConversionGenerator>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Text::ITextReverseConversionGenerator2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Text::ITextReverseConversionGeneratorFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Text::IUnicodeCharactersStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Text::IWordSegment>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Text::IWordsSegmenter>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Text::IWordsSegmenterFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Data::Text::AlternateWordForm>{ using type = class_category; };
    template <> struct category<winrt::Windows::Data::Text::SelectableWordSegment>{ using type = class_category; };
    template <> struct category<winrt::Windows::Data::Text::SelectableWordsSegmenter>{ using type = class_category; };
    template <> struct category<winrt::Windows::Data::Text::SemanticTextQuery>{ using type = class_category; };
    template <> struct category<winrt::Windows::Data::Text::TextConversionGenerator>{ using type = class_category; };
    template <> struct category<winrt::Windows::Data::Text::TextPhoneme>{ using type = class_category; };
    template <> struct category<winrt::Windows::Data::Text::TextPredictionGenerator>{ using type = class_category; };
    template <> struct category<winrt::Windows::Data::Text::TextReverseConversionGenerator>{ using type = class_category; };
    template <> struct category<winrt::Windows::Data::Text::UnicodeCharacters>{ using type = class_category; };
    template <> struct category<winrt::Windows::Data::Text::WordSegment>{ using type = class_category; };
    template <> struct category<winrt::Windows::Data::Text::WordsSegmenter>{ using type = class_category; };
    template <> struct category<winrt::Windows::Data::Text::AlternateNormalizationFormat>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Data::Text::TextPredictionOptions>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Data::Text::UnicodeGeneralCategory>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Data::Text::UnicodeNumericType>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Data::Text::TextSegment>{ using type = struct_category<uint32_t, uint32_t>; };
    template <> struct category<winrt::Windows::Data::Text::SelectableWordSegmentsTokenizingHandler>{ using type = delegate_category; };
    template <> struct category<winrt::Windows::Data::Text::WordSegmentsTokenizingHandler>{ using type = delegate_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::AlternateWordForm> = L"Windows.Data.Text.AlternateWordForm";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::SelectableWordSegment> = L"Windows.Data.Text.SelectableWordSegment";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::SelectableWordsSegmenter> = L"Windows.Data.Text.SelectableWordsSegmenter";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::SemanticTextQuery> = L"Windows.Data.Text.SemanticTextQuery";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::TextConversionGenerator> = L"Windows.Data.Text.TextConversionGenerator";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::TextPhoneme> = L"Windows.Data.Text.TextPhoneme";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::TextPredictionGenerator> = L"Windows.Data.Text.TextPredictionGenerator";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::TextReverseConversionGenerator> = L"Windows.Data.Text.TextReverseConversionGenerator";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::UnicodeCharacters> = L"Windows.Data.Text.UnicodeCharacters";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::WordSegment> = L"Windows.Data.Text.WordSegment";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::WordsSegmenter> = L"Windows.Data.Text.WordsSegmenter";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::AlternateNormalizationFormat> = L"Windows.Data.Text.AlternateNormalizationFormat";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::TextPredictionOptions> = L"Windows.Data.Text.TextPredictionOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::UnicodeGeneralCategory> = L"Windows.Data.Text.UnicodeGeneralCategory";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::UnicodeNumericType> = L"Windows.Data.Text.UnicodeNumericType";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::TextSegment> = L"Windows.Data.Text.TextSegment";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::IAlternateWordForm> = L"Windows.Data.Text.IAlternateWordForm";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::ISelectableWordSegment> = L"Windows.Data.Text.ISelectableWordSegment";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::ISelectableWordsSegmenter> = L"Windows.Data.Text.ISelectableWordsSegmenter";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::ISelectableWordsSegmenterFactory> = L"Windows.Data.Text.ISelectableWordsSegmenterFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::ISemanticTextQuery> = L"Windows.Data.Text.ISemanticTextQuery";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::ISemanticTextQueryFactory> = L"Windows.Data.Text.ISemanticTextQueryFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::ITextConversionGenerator> = L"Windows.Data.Text.ITextConversionGenerator";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::ITextConversionGeneratorFactory> = L"Windows.Data.Text.ITextConversionGeneratorFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::ITextPhoneme> = L"Windows.Data.Text.ITextPhoneme";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::ITextPredictionGenerator> = L"Windows.Data.Text.ITextPredictionGenerator";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::ITextPredictionGenerator2> = L"Windows.Data.Text.ITextPredictionGenerator2";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::ITextPredictionGeneratorFactory> = L"Windows.Data.Text.ITextPredictionGeneratorFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::ITextReverseConversionGenerator> = L"Windows.Data.Text.ITextReverseConversionGenerator";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::ITextReverseConversionGenerator2> = L"Windows.Data.Text.ITextReverseConversionGenerator2";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::ITextReverseConversionGeneratorFactory> = L"Windows.Data.Text.ITextReverseConversionGeneratorFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::IUnicodeCharactersStatics> = L"Windows.Data.Text.IUnicodeCharactersStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::IWordSegment> = L"Windows.Data.Text.IWordSegment";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::IWordsSegmenter> = L"Windows.Data.Text.IWordsSegmenter";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::IWordsSegmenterFactory> = L"Windows.Data.Text.IWordsSegmenterFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::SelectableWordSegmentsTokenizingHandler> = L"Windows.Data.Text.SelectableWordSegmentsTokenizingHandler";
    template <> inline constexpr auto& name_v<winrt::Windows::Data::Text::WordSegmentsTokenizingHandler> = L"Windows.Data.Text.WordSegmentsTokenizingHandler";
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Text::IAlternateWordForm>{ 0x47396C1E,0x51B9,0x4207,{ 0x91,0x46,0x24,0x8E,0x63,0x6A,0x1D,0x1D } }; // 47396C1E-51B9-4207-9146-248E636A1D1D
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Text::ISelectableWordSegment>{ 0x916A4CB7,0x8AA7,0x4C78,{ 0xB3,0x74,0x5D,0xED,0xB7,0x52,0xE6,0x0B } }; // 916A4CB7-8AA7-4C78-B374-5DEDB752E60B
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Text::ISelectableWordsSegmenter>{ 0xF6DC31E7,0x4B13,0x45C5,{ 0x88,0x97,0x7D,0x71,0x26,0x9E,0x08,0x5D } }; // F6DC31E7-4B13-45C5-8897-7D71269E085D
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Text::ISelectableWordsSegmenterFactory>{ 0x8C7A7648,0x6057,0x4339,{ 0xBC,0x70,0xF2,0x10,0x01,0x0A,0x41,0x50 } }; // 8C7A7648-6057-4339-BC70-F210010A4150
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Text::ISemanticTextQuery>{ 0x6A1CAB51,0x1FB2,0x4909,{ 0x80,0xB8,0x35,0x73,0x1A,0x2B,0x3E,0x7F } }; // 6A1CAB51-1FB2-4909-80B8-35731A2B3E7F
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Text::ISemanticTextQueryFactory>{ 0x238C0503,0xF995,0x4587,{ 0x87,0x77,0xA2,0xB7,0xD8,0x0A,0xCF,0xEF } }; // 238C0503-F995-4587-8777-A2B7D80ACFEF
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Text::ITextConversionGenerator>{ 0x03606A5E,0x2AA9,0x4AB6,{ 0xAF,0x8B,0xA5,0x62,0xB6,0x3A,0x89,0x92 } }; // 03606A5E-2AA9-4AB6-AF8B-A562B63A8992
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Text::ITextConversionGeneratorFactory>{ 0xFCAA3781,0x3083,0x49AB,{ 0xBE,0x15,0x56,0xDF,0xBB,0xB7,0x4D,0x6F } }; // FCAA3781-3083-49AB-BE15-56DFBBB74D6F
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Text::ITextPhoneme>{ 0x9362A40A,0x9B7A,0x4569,{ 0x94,0xCF,0xD8,0x4F,0x2F,0x38,0xCF,0x9B } }; // 9362A40A-9B7A-4569-94CF-D84F2F38CF9B
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Text::ITextPredictionGenerator>{ 0x5EACAB07,0xABF1,0x4CB6,{ 0x9D,0x9E,0x32,0x6F,0x2B,0x46,0x87,0x56 } }; // 5EACAB07-ABF1-4CB6-9D9E-326F2B468756
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Text::ITextPredictionGenerator2>{ 0xB84723B8,0x2C77,0x486A,{ 0x90,0x0A,0xA3,0x45,0x3E,0xED,0xC1,0x5D } }; // B84723B8-2C77-486A-900A-A3453EEDC15D
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Text::ITextPredictionGeneratorFactory>{ 0x7257B416,0x8BA2,0x4751,{ 0x9D,0x30,0x9D,0x85,0x43,0x56,0x53,0xA2 } }; // 7257B416-8BA2-4751-9D30-9D85435653A2
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Text::ITextReverseConversionGenerator>{ 0x51E7F514,0x9C51,0x4D86,{ 0xAE,0x1B,0xB4,0x98,0xFB,0xAD,0x83,0x13 } }; // 51E7F514-9C51-4D86-AE1B-B498FBAD8313
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Text::ITextReverseConversionGenerator2>{ 0x1AAFD2EC,0x85D6,0x46FD,{ 0x82,0x8A,0x3A,0x48,0x30,0xFA,0x6E,0x18 } }; // 1AAFD2EC-85D6-46FD-828A-3A4830FA6E18
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Text::ITextReverseConversionGeneratorFactory>{ 0x63BED326,0x1FDA,0x41F6,{ 0x89,0xD5,0x23,0xDD,0xEA,0x3C,0x72,0x9A } }; // 63BED326-1FDA-41F6-89D5-23DDEA3C729A
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Text::IUnicodeCharactersStatics>{ 0x97909E87,0x9291,0x4F91,{ 0xB6,0xC8,0xB6,0xE3,0x59,0xD7,0xA7,0xFB } }; // 97909E87-9291-4F91-B6C8-B6E359D7A7FB
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Text::IWordSegment>{ 0xD2D4BA6D,0x987C,0x4CC0,{ 0xB6,0xBD,0xD4,0x9A,0x11,0xB3,0x8F,0x9A } }; // D2D4BA6D-987C-4CC0-B6BD-D49A11B38F9A
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Text::IWordsSegmenter>{ 0x86B4D4D1,0xB2FE,0x4E34,{ 0xA8,0x1D,0x66,0x64,0x03,0x00,0x45,0x4F } }; // 86B4D4D1-B2FE-4E34-A81D-66640300454F
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Text::IWordsSegmenterFactory>{ 0xE6977274,0xFC35,0x455C,{ 0x8B,0xFB,0x6D,0x7F,0x46,0x53,0xCA,0x97 } }; // E6977274-FC35-455C-8BFB-6D7F4653CA97
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Text::SelectableWordSegmentsTokenizingHandler>{ 0x3A3DFC9C,0xAEDE,0x4DC7,{ 0x9E,0x6C,0x41,0xC0,0x44,0xBD,0x35,0x92 } }; // 3A3DFC9C-AEDE-4DC7-9E6C-41C044BD3592
    template <> inline constexpr guid guid_v<winrt::Windows::Data::Text::WordSegmentsTokenizingHandler>{ 0xA5DD6357,0xBF2A,0x4C4F,{ 0xA3,0x1F,0x29,0xE7,0x1C,0x6F,0x8B,0x35 } }; // A5DD6357-BF2A-4C4F-A31F-29E71C6F8B35
    template <> struct default_interface<winrt::Windows::Data::Text::AlternateWordForm>{ using type = winrt::Windows::Data::Text::IAlternateWordForm; };
    template <> struct default_interface<winrt::Windows::Data::Text::SelectableWordSegment>{ using type = winrt::Windows::Data::Text::ISelectableWordSegment; };
    template <> struct default_interface<winrt::Windows::Data::Text::SelectableWordsSegmenter>{ using type = winrt::Windows::Data::Text::ISelectableWordsSegmenter; };
    template <> struct default_interface<winrt::Windows::Data::Text::SemanticTextQuery>{ using type = winrt::Windows::Data::Text::ISemanticTextQuery; };
    template <> struct default_interface<winrt::Windows::Data::Text::TextConversionGenerator>{ using type = winrt::Windows::Data::Text::ITextConversionGenerator; };
    template <> struct default_interface<winrt::Windows::Data::Text::TextPhoneme>{ using type = winrt::Windows::Data::Text::ITextPhoneme; };
    template <> struct default_interface<winrt::Windows::Data::Text::TextPredictionGenerator>{ using type = winrt::Windows::Data::Text::ITextPredictionGenerator; };
    template <> struct default_interface<winrt::Windows::Data::Text::TextReverseConversionGenerator>{ using type = winrt::Windows::Data::Text::ITextReverseConversionGenerator; };
    template <> struct default_interface<winrt::Windows::Data::Text::WordSegment>{ using type = winrt::Windows::Data::Text::IWordSegment; };
    template <> struct default_interface<winrt::Windows::Data::Text::WordsSegmenter>{ using type = winrt::Windows::Data::Text::IWordsSegmenter; };
    template <> struct abi<winrt::Windows::Data::Text::IAlternateWordForm>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_SourceTextSegment(struct struct_Windows_Data_Text_TextSegment*) noexcept = 0;
            virtual int32_t __stdcall get_AlternateText(void**) noexcept = 0;
            virtual int32_t __stdcall get_NormalizationFormat(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Text::ISelectableWordSegment>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Text(void**) noexcept = 0;
            virtual int32_t __stdcall get_SourceTextSegment(struct struct_Windows_Data_Text_TextSegment*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Text::ISelectableWordsSegmenter>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ResolvedLanguage(void**) noexcept = 0;
            virtual int32_t __stdcall GetTokenAt(void*, uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetTokens(void*, void**) noexcept = 0;
            virtual int32_t __stdcall Tokenize(void*, uint32_t, void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Text::ISelectableWordsSegmenterFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateWithLanguage(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Text::ISemanticTextQuery>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Find(void*, void**) noexcept = 0;
            virtual int32_t __stdcall FindInProperty(void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Text::ISemanticTextQueryFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(void*, void**) noexcept = 0;
            virtual int32_t __stdcall CreateWithLanguage(void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Text::ITextConversionGenerator>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ResolvedLanguage(void**) noexcept = 0;
            virtual int32_t __stdcall get_LanguageAvailableButNotInstalled(bool*) noexcept = 0;
            virtual int32_t __stdcall GetCandidatesAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetCandidatesWithMaxCountAsync(void*, uint32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Text::ITextConversionGeneratorFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Text::ITextPhoneme>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DisplayText(void**) noexcept = 0;
            virtual int32_t __stdcall get_ReadingText(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Text::ITextPredictionGenerator>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ResolvedLanguage(void**) noexcept = 0;
            virtual int32_t __stdcall get_LanguageAvailableButNotInstalled(bool*) noexcept = 0;
            virtual int32_t __stdcall GetCandidatesAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetCandidatesWithMaxCountAsync(void*, uint32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Text::ITextPredictionGenerator2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetCandidatesWithParametersAsync(void*, uint32_t, uint32_t, void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetNextWordCandidatesAsync(uint32_t, void*, void**) noexcept = 0;
            virtual int32_t __stdcall get_InputScope(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_InputScope(int32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Text::ITextPredictionGeneratorFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Text::ITextReverseConversionGenerator>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ResolvedLanguage(void**) noexcept = 0;
            virtual int32_t __stdcall get_LanguageAvailableButNotInstalled(bool*) noexcept = 0;
            virtual int32_t __stdcall ConvertBackAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Text::ITextReverseConversionGenerator2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetPhonemesAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Text::ITextReverseConversionGeneratorFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Create(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Text::IUnicodeCharactersStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetCodepointFromSurrogatePair(uint32_t, uint32_t, uint32_t*) noexcept = 0;
            virtual int32_t __stdcall GetSurrogatePairFromCodepoint(uint32_t, char16_t*, char16_t*) noexcept = 0;
            virtual int32_t __stdcall IsHighSurrogate(uint32_t, bool*) noexcept = 0;
            virtual int32_t __stdcall IsLowSurrogate(uint32_t, bool*) noexcept = 0;
            virtual int32_t __stdcall IsSupplementary(uint32_t, bool*) noexcept = 0;
            virtual int32_t __stdcall IsNoncharacter(uint32_t, bool*) noexcept = 0;
            virtual int32_t __stdcall IsWhitespace(uint32_t, bool*) noexcept = 0;
            virtual int32_t __stdcall IsAlphabetic(uint32_t, bool*) noexcept = 0;
            virtual int32_t __stdcall IsCased(uint32_t, bool*) noexcept = 0;
            virtual int32_t __stdcall IsUppercase(uint32_t, bool*) noexcept = 0;
            virtual int32_t __stdcall IsLowercase(uint32_t, bool*) noexcept = 0;
            virtual int32_t __stdcall IsIdStart(uint32_t, bool*) noexcept = 0;
            virtual int32_t __stdcall IsIdContinue(uint32_t, bool*) noexcept = 0;
            virtual int32_t __stdcall IsGraphemeBase(uint32_t, bool*) noexcept = 0;
            virtual int32_t __stdcall IsGraphemeExtend(uint32_t, bool*) noexcept = 0;
            virtual int32_t __stdcall GetNumericType(uint32_t, int32_t*) noexcept = 0;
            virtual int32_t __stdcall GetGeneralCategory(uint32_t, int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Text::IWordSegment>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Text(void**) noexcept = 0;
            virtual int32_t __stdcall get_SourceTextSegment(struct struct_Windows_Data_Text_TextSegment*) noexcept = 0;
            virtual int32_t __stdcall get_AlternateForms(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Text::IWordsSegmenter>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ResolvedLanguage(void**) noexcept = 0;
            virtual int32_t __stdcall GetTokenAt(void*, uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetTokens(void*, void**) noexcept = 0;
            virtual int32_t __stdcall Tokenize(void*, uint32_t, void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Text::IWordsSegmenterFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateWithLanguage(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Text::SelectableWordSegmentsTokenizingHandler>
    {
        struct __declspec(novtable) type : unknown_abi
        {
            virtual int32_t __stdcall Invoke(void*, void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Data::Text::WordSegmentsTokenizingHandler>
    {
        struct __declspec(novtable) type : unknown_abi
        {
            virtual int32_t __stdcall Invoke(void*, void*) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Data_Text_IAlternateWordForm
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Data::Text::TextSegment) SourceTextSegment() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) AlternateText() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Data::Text::AlternateNormalizationFormat) NormalizationFormat() const;
    };
    template <> struct consume<winrt::Windows::Data::Text::IAlternateWordForm>
    {
        template <typename D> using type = consume_Windows_Data_Text_IAlternateWordForm<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Text_ISelectableWordSegment
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Text() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Data::Text::TextSegment) SourceTextSegment() const;
    };
    template <> struct consume<winrt::Windows::Data::Text::ISelectableWordSegment>
    {
        template <typename D> using type = consume_Windows_Data_Text_ISelectableWordSegment<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Text_ISelectableWordsSegmenter
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ResolvedLanguage() const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Text::SelectableWordSegment) GetTokenAt(param::hstring const& text, uint32_t startIndex) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Data::Text::SelectableWordSegment>) GetTokens(param::hstring const& text) const;
        WINRT_IMPL_AUTO(void) Tokenize(param::hstring const& text, uint32_t startIndex, winrt::Windows::Data::Text::SelectableWordSegmentsTokenizingHandler const& handler) const;
    };
    template <> struct consume<winrt::Windows::Data::Text::ISelectableWordsSegmenter>
    {
        template <typename D> using type = consume_Windows_Data_Text_ISelectableWordsSegmenter<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Text_ISelectableWordsSegmenterFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Data::Text::SelectableWordsSegmenter) CreateWithLanguage(param::hstring const& language) const;
    };
    template <> struct consume<winrt::Windows::Data::Text::ISelectableWordsSegmenterFactory>
    {
        template <typename D> using type = consume_Windows_Data_Text_ISelectableWordsSegmenterFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Text_ISemanticTextQuery
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Data::Text::TextSegment>) Find(param::hstring const& content) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Data::Text::TextSegment>) FindInProperty(param::hstring const& propertyContent, param::hstring const& propertyName) const;
    };
    template <> struct consume<winrt::Windows::Data::Text::ISemanticTextQuery>
    {
        template <typename D> using type = consume_Windows_Data_Text_ISemanticTextQuery<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Text_ISemanticTextQueryFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Data::Text::SemanticTextQuery) Create(param::hstring const& aqsFilter) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Text::SemanticTextQuery) CreateWithLanguage(param::hstring const& aqsFilter, param::hstring const& filterLanguage) const;
    };
    template <> struct consume<winrt::Windows::Data::Text::ISemanticTextQueryFactory>
    {
        template <typename D> using type = consume_Windows_Data_Text_ISemanticTextQueryFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Text_ITextConversionGenerator
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ResolvedLanguage() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) LanguageAvailableButNotInstalled() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<hstring>>) GetCandidatesAsync(param::hstring const& input) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<hstring>>) GetCandidatesAsync(param::hstring const& input, uint32_t maxCandidates) const;
    };
    template <> struct consume<winrt::Windows::Data::Text::ITextConversionGenerator>
    {
        template <typename D> using type = consume_Windows_Data_Text_ITextConversionGenerator<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Text_ITextConversionGeneratorFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Data::Text::TextConversionGenerator) Create(param::hstring const& languageTag) const;
    };
    template <> struct consume<winrt::Windows::Data::Text::ITextConversionGeneratorFactory>
    {
        template <typename D> using type = consume_Windows_Data_Text_ITextConversionGeneratorFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Text_ITextPhoneme
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DisplayText() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ReadingText() const;
    };
    template <> struct consume<winrt::Windows::Data::Text::ITextPhoneme>
    {
        template <typename D> using type = consume_Windows_Data_Text_ITextPhoneme<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Text_ITextPredictionGenerator
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ResolvedLanguage() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) LanguageAvailableButNotInstalled() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<hstring>>) GetCandidatesAsync(param::hstring const& input) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<hstring>>) GetCandidatesAsync(param::hstring const& input, uint32_t maxCandidates) const;
    };
    template <> struct consume<winrt::Windows::Data::Text::ITextPredictionGenerator>
    {
        template <typename D> using type = consume_Windows_Data_Text_ITextPredictionGenerator<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Text_ITextPredictionGenerator2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<hstring>>) GetCandidatesAsync(param::hstring const& input, uint32_t maxCandidates, winrt::Windows::Data::Text::TextPredictionOptions const& predictionOptions, param::async_iterable<hstring> const& previousStrings) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<hstring>>) GetNextWordCandidatesAsync(uint32_t maxCandidates, param::async_iterable<hstring> const& previousStrings) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Text::Core::CoreTextInputScope) InputScope() const;
        WINRT_IMPL_AUTO(void) InputScope(winrt::Windows::UI::Text::Core::CoreTextInputScope const& value) const;
    };
    template <> struct consume<winrt::Windows::Data::Text::ITextPredictionGenerator2>
    {
        template <typename D> using type = consume_Windows_Data_Text_ITextPredictionGenerator2<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Text_ITextPredictionGeneratorFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Data::Text::TextPredictionGenerator) Create(param::hstring const& languageTag) const;
    };
    template <> struct consume<winrt::Windows::Data::Text::ITextPredictionGeneratorFactory>
    {
        template <typename D> using type = consume_Windows_Data_Text_ITextPredictionGeneratorFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Text_ITextReverseConversionGenerator
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ResolvedLanguage() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) LanguageAvailableButNotInstalled() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) ConvertBackAsync(param::hstring const& input) const;
    };
    template <> struct consume<winrt::Windows::Data::Text::ITextReverseConversionGenerator>
    {
        template <typename D> using type = consume_Windows_Data_Text_ITextReverseConversionGenerator<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Text_ITextReverseConversionGenerator2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Data::Text::TextPhoneme>>) GetPhonemesAsync(param::hstring const& input) const;
    };
    template <> struct consume<winrt::Windows::Data::Text::ITextReverseConversionGenerator2>
    {
        template <typename D> using type = consume_Windows_Data_Text_ITextReverseConversionGenerator2<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Text_ITextReverseConversionGeneratorFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Data::Text::TextReverseConversionGenerator) Create(param::hstring const& languageTag) const;
    };
    template <> struct consume<winrt::Windows::Data::Text::ITextReverseConversionGeneratorFactory>
    {
        template <typename D> using type = consume_Windows_Data_Text_ITextReverseConversionGeneratorFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Text_IUnicodeCharactersStatics
    {
        WINRT_IMPL_AUTO(uint32_t) GetCodepointFromSurrogatePair(uint32_t highSurrogate, uint32_t lowSurrogate) const;
        WINRT_IMPL_AUTO(void) GetSurrogatePairFromCodepoint(uint32_t codepoint, char16_t& highSurrogate, char16_t& lowSurrogate) const;
        WINRT_IMPL_AUTO(bool) IsHighSurrogate(uint32_t codepoint) const;
        WINRT_IMPL_AUTO(bool) IsLowSurrogate(uint32_t codepoint) const;
        WINRT_IMPL_AUTO(bool) IsSupplementary(uint32_t codepoint) const;
        WINRT_IMPL_AUTO(bool) IsNoncharacter(uint32_t codepoint) const;
        WINRT_IMPL_AUTO(bool) IsWhitespace(uint32_t codepoint) const;
        WINRT_IMPL_AUTO(bool) IsAlphabetic(uint32_t codepoint) const;
        WINRT_IMPL_AUTO(bool) IsCased(uint32_t codepoint) const;
        WINRT_IMPL_AUTO(bool) IsUppercase(uint32_t codepoint) const;
        WINRT_IMPL_AUTO(bool) IsLowercase(uint32_t codepoint) const;
        WINRT_IMPL_AUTO(bool) IsIdStart(uint32_t codepoint) const;
        WINRT_IMPL_AUTO(bool) IsIdContinue(uint32_t codepoint) const;
        WINRT_IMPL_AUTO(bool) IsGraphemeBase(uint32_t codepoint) const;
        WINRT_IMPL_AUTO(bool) IsGraphemeExtend(uint32_t codepoint) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Text::UnicodeNumericType) GetNumericType(uint32_t codepoint) const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Text::UnicodeGeneralCategory) GetGeneralCategory(uint32_t codepoint) const;
    };
    template <> struct consume<winrt::Windows::Data::Text::IUnicodeCharactersStatics>
    {
        template <typename D> using type = consume_Windows_Data_Text_IUnicodeCharactersStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Text_IWordSegment
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Text() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Data::Text::TextSegment) SourceTextSegment() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Data::Text::AlternateWordForm>) AlternateForms() const;
    };
    template <> struct consume<winrt::Windows::Data::Text::IWordSegment>
    {
        template <typename D> using type = consume_Windows_Data_Text_IWordSegment<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Text_IWordsSegmenter
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ResolvedLanguage() const;
        WINRT_IMPL_AUTO(winrt::Windows::Data::Text::WordSegment) GetTokenAt(param::hstring const& text, uint32_t startIndex) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Data::Text::WordSegment>) GetTokens(param::hstring const& text) const;
        WINRT_IMPL_AUTO(void) Tokenize(param::hstring const& text, uint32_t startIndex, winrt::Windows::Data::Text::WordSegmentsTokenizingHandler const& handler) const;
    };
    template <> struct consume<winrt::Windows::Data::Text::IWordsSegmenter>
    {
        template <typename D> using type = consume_Windows_Data_Text_IWordsSegmenter<D>;
    };
    template <typename D>
    struct consume_Windows_Data_Text_IWordsSegmenterFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Data::Text::WordsSegmenter) CreateWithLanguage(param::hstring const& language) const;
    };
    template <> struct consume<winrt::Windows::Data::Text::IWordsSegmenterFactory>
    {
        template <typename D> using type = consume_Windows_Data_Text_IWordsSegmenterFactory<D>;
    };
    struct struct_Windows_Data_Text_TextSegment
    {
        uint32_t StartPosition;
        uint32_t Length;
    };
    template <> struct abi<Windows::Data::Text::TextSegment>
    {
        using type = struct_Windows_Data_Text_TextSegment;
    };
}
#endif
