// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_Xaml_Documents_0_H
#define WINRT_Windows_UI_Xaml_Documents_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct EventRegistrationToken;
    struct Rect;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
    struct Uri;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IVector;
}
WINRT_EXPORT namespace winrt::Windows::UI::Core
{
    enum class CoreCursorType : int32_t;
}
WINRT_EXPORT namespace winrt::Windows::UI::Text
{
    struct ContentLinkInfo;
    enum class FontStretch : int32_t;
    enum class FontStyle : int32_t;
    struct FontWeight;
    enum class TextDecorations : uint32_t;
}
WINRT_EXPORT namespace winrt::Windows::UI::Xaml
{
    struct DependencyObject;
    struct DependencyProperty;
    enum class ElementSoundMode : int32_t;
    enum class FlowDirection : int32_t;
    enum class FocusState : int32_t;
    enum class FontCapitals : int32_t;
    enum class FontEastAsianLanguage : int32_t;
    enum class FontEastAsianWidths : int32_t;
    enum class FontFraction : int32_t;
    enum class FontNumeralAlignment : int32_t;
    enum class FontNumeralStyle : int32_t;
    enum class FontVariants : int32_t;
    struct FrameworkElement;
    enum class LineStackingStrategy : int32_t;
    struct RoutedEventHandler;
    enum class TextAlignment : int32_t;
    struct Thickness;
    struct UIElement;
    struct XamlRoot;
}
WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Input
{
    struct AccessKeyDisplayDismissedEventArgs;
    struct AccessKeyDisplayRequestedEventArgs;
    struct AccessKeyInvokedEventArgs;
    enum class KeyTipPlacementMode : int32_t;
    enum class XYFocusNavigationStrategy : int32_t;
}
WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Media
{
    struct Brush;
    struct FontFamily;
    enum class StyleSimulations : int32_t;
}
WINRT_EXPORT namespace winrt::Windows::UI::Xaml::Documents
{
    enum class LogicalDirection : int32_t
    {
        Backward = 0,
        Forward = 1,
    };
    enum class UnderlineStyle : int32_t
    {
        None = 0,
        Single = 1,
    };
    struct IBlock;
    struct IBlock2;
    struct IBlockFactory;
    struct IBlockStatics;
    struct IBlockStatics2;
    struct IBold;
    struct IContactContentLinkProvider;
    struct IContentLink;
    struct IContentLinkInvokedEventArgs;
    struct IContentLinkProvider;
    struct IContentLinkProviderCollection;
    struct IContentLinkProviderFactory;
    struct IContentLinkStatics;
    struct IGlyphs;
    struct IGlyphs2;
    struct IGlyphsStatics;
    struct IGlyphsStatics2;
    struct IHyperlink;
    struct IHyperlink2;
    struct IHyperlink3;
    struct IHyperlink4;
    struct IHyperlink5;
    struct IHyperlinkClickEventArgs;
    struct IHyperlinkStatics;
    struct IHyperlinkStatics2;
    struct IHyperlinkStatics3;
    struct IHyperlinkStatics4;
    struct IHyperlinkStatics5;
    struct IInline;
    struct IInlineFactory;
    struct IInlineUIContainer;
    struct IItalic;
    struct ILineBreak;
    struct IParagraph;
    struct IParagraphStatics;
    struct IPlaceContentLinkProvider;
    struct IRun;
    struct IRunStatics;
    struct ISpan;
    struct ISpanFactory;
    struct ITextElement;
    struct ITextElement2;
    struct ITextElement3;
    struct ITextElement4;
    struct ITextElement5;
    struct ITextElementFactory;
    struct ITextElementOverrides;
    struct ITextElementStatics;
    struct ITextElementStatics2;
    struct ITextElementStatics3;
    struct ITextElementStatics4;
    struct ITextHighlighter;
    struct ITextHighlighterBase;
    struct ITextHighlighterBaseFactory;
    struct ITextHighlighterFactory;
    struct ITextHighlighterStatics;
    struct ITextPointer;
    struct ITypography;
    struct ITypographyStatics;
    struct IUnderline;
    struct Block;
    struct BlockCollection;
    struct Bold;
    struct ContactContentLinkProvider;
    struct ContentLink;
    struct ContentLinkInvokedEventArgs;
    struct ContentLinkProvider;
    struct ContentLinkProviderCollection;
    struct Glyphs;
    struct Hyperlink;
    struct HyperlinkClickEventArgs;
    struct Inline;
    struct InlineCollection;
    struct InlineUIContainer;
    struct Italic;
    struct LineBreak;
    struct Paragraph;
    struct PlaceContentLinkProvider;
    struct Run;
    struct Span;
    struct TextElement;
    struct TextHighlighter;
    struct TextHighlighterBase;
    struct TextPointer;
    struct Typography;
    struct Underline;
    struct TextRange;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IBlock>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IBlock2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IBlockFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IBlockStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IBlockStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IBold>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IContactContentLinkProvider>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IContentLink>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IContentLinkInvokedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IContentLinkProvider>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IContentLinkProviderCollection>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IContentLinkProviderFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IContentLinkStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IGlyphs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IGlyphs2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IGlyphsStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IGlyphsStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IHyperlink>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IHyperlink2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IHyperlink3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IHyperlink4>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IHyperlink5>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IHyperlinkClickEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics4>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics5>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IInline>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IInlineFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IInlineUIContainer>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IItalic>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::ILineBreak>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IParagraph>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IParagraphStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IPlaceContentLinkProvider>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IRun>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IRunStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::ISpan>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::ISpanFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::ITextElement>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::ITextElement2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::ITextElement3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::ITextElement4>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::ITextElement5>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::ITextElementFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::ITextElementOverrides>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::ITextElementStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::ITextElementStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::ITextElementStatics3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::ITextElementStatics4>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::ITextHighlighter>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::ITextHighlighterBase>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::ITextHighlighterBaseFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::ITextHighlighterFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::ITextHighlighterStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::ITextPointer>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::ITypography>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::ITypographyStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::IUnderline>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::Block>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::BlockCollection>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::Bold>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::ContactContentLinkProvider>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::ContentLink>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::ContentLinkInvokedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::ContentLinkProvider>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::ContentLinkProviderCollection>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::Glyphs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::Hyperlink>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::HyperlinkClickEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::Inline>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::InlineCollection>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::InlineUIContainer>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::Italic>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::LineBreak>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::Paragraph>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::PlaceContentLinkProvider>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::Run>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::Span>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::TextElement>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::TextHighlighter>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::TextHighlighterBase>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::TextPointer>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::Typography>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::Underline>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::LogicalDirection>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::UnderlineStyle>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::Xaml::Documents::TextRange>{ using type = struct_category<int32_t, int32_t>; };
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::Block> = L"Windows.UI.Xaml.Documents.Block";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::BlockCollection> = L"Windows.UI.Xaml.Documents.BlockCollection";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::Bold> = L"Windows.UI.Xaml.Documents.Bold";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::ContactContentLinkProvider> = L"Windows.UI.Xaml.Documents.ContactContentLinkProvider";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::ContentLink> = L"Windows.UI.Xaml.Documents.ContentLink";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::ContentLinkInvokedEventArgs> = L"Windows.UI.Xaml.Documents.ContentLinkInvokedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::ContentLinkProvider> = L"Windows.UI.Xaml.Documents.ContentLinkProvider";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::ContentLinkProviderCollection> = L"Windows.UI.Xaml.Documents.ContentLinkProviderCollection";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::Glyphs> = L"Windows.UI.Xaml.Documents.Glyphs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::Hyperlink> = L"Windows.UI.Xaml.Documents.Hyperlink";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::HyperlinkClickEventArgs> = L"Windows.UI.Xaml.Documents.HyperlinkClickEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::Inline> = L"Windows.UI.Xaml.Documents.Inline";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::InlineCollection> = L"Windows.UI.Xaml.Documents.InlineCollection";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::InlineUIContainer> = L"Windows.UI.Xaml.Documents.InlineUIContainer";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::Italic> = L"Windows.UI.Xaml.Documents.Italic";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::LineBreak> = L"Windows.UI.Xaml.Documents.LineBreak";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::Paragraph> = L"Windows.UI.Xaml.Documents.Paragraph";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::PlaceContentLinkProvider> = L"Windows.UI.Xaml.Documents.PlaceContentLinkProvider";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::Run> = L"Windows.UI.Xaml.Documents.Run";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::Span> = L"Windows.UI.Xaml.Documents.Span";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::TextElement> = L"Windows.UI.Xaml.Documents.TextElement";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::TextHighlighter> = L"Windows.UI.Xaml.Documents.TextHighlighter";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::TextHighlighterBase> = L"Windows.UI.Xaml.Documents.TextHighlighterBase";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::TextPointer> = L"Windows.UI.Xaml.Documents.TextPointer";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::Typography> = L"Windows.UI.Xaml.Documents.Typography";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::Underline> = L"Windows.UI.Xaml.Documents.Underline";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::LogicalDirection> = L"Windows.UI.Xaml.Documents.LogicalDirection";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::UnderlineStyle> = L"Windows.UI.Xaml.Documents.UnderlineStyle";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::TextRange> = L"Windows.UI.Xaml.Documents.TextRange";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IBlock> = L"Windows.UI.Xaml.Documents.IBlock";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IBlock2> = L"Windows.UI.Xaml.Documents.IBlock2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IBlockFactory> = L"Windows.UI.Xaml.Documents.IBlockFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IBlockStatics> = L"Windows.UI.Xaml.Documents.IBlockStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IBlockStatics2> = L"Windows.UI.Xaml.Documents.IBlockStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IBold> = L"Windows.UI.Xaml.Documents.IBold";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IContactContentLinkProvider> = L"Windows.UI.Xaml.Documents.IContactContentLinkProvider";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IContentLink> = L"Windows.UI.Xaml.Documents.IContentLink";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IContentLinkInvokedEventArgs> = L"Windows.UI.Xaml.Documents.IContentLinkInvokedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IContentLinkProvider> = L"Windows.UI.Xaml.Documents.IContentLinkProvider";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IContentLinkProviderCollection> = L"Windows.UI.Xaml.Documents.IContentLinkProviderCollection";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IContentLinkProviderFactory> = L"Windows.UI.Xaml.Documents.IContentLinkProviderFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IContentLinkStatics> = L"Windows.UI.Xaml.Documents.IContentLinkStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IGlyphs> = L"Windows.UI.Xaml.Documents.IGlyphs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IGlyphs2> = L"Windows.UI.Xaml.Documents.IGlyphs2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IGlyphsStatics> = L"Windows.UI.Xaml.Documents.IGlyphsStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IGlyphsStatics2> = L"Windows.UI.Xaml.Documents.IGlyphsStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IHyperlink> = L"Windows.UI.Xaml.Documents.IHyperlink";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IHyperlink2> = L"Windows.UI.Xaml.Documents.IHyperlink2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IHyperlink3> = L"Windows.UI.Xaml.Documents.IHyperlink3";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IHyperlink4> = L"Windows.UI.Xaml.Documents.IHyperlink4";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IHyperlink5> = L"Windows.UI.Xaml.Documents.IHyperlink5";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IHyperlinkClickEventArgs> = L"Windows.UI.Xaml.Documents.IHyperlinkClickEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics> = L"Windows.UI.Xaml.Documents.IHyperlinkStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics2> = L"Windows.UI.Xaml.Documents.IHyperlinkStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics3> = L"Windows.UI.Xaml.Documents.IHyperlinkStatics3";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics4> = L"Windows.UI.Xaml.Documents.IHyperlinkStatics4";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics5> = L"Windows.UI.Xaml.Documents.IHyperlinkStatics5";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IInline> = L"Windows.UI.Xaml.Documents.IInline";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IInlineFactory> = L"Windows.UI.Xaml.Documents.IInlineFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IInlineUIContainer> = L"Windows.UI.Xaml.Documents.IInlineUIContainer";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IItalic> = L"Windows.UI.Xaml.Documents.IItalic";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::ILineBreak> = L"Windows.UI.Xaml.Documents.ILineBreak";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IParagraph> = L"Windows.UI.Xaml.Documents.IParagraph";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IParagraphStatics> = L"Windows.UI.Xaml.Documents.IParagraphStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IPlaceContentLinkProvider> = L"Windows.UI.Xaml.Documents.IPlaceContentLinkProvider";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IRun> = L"Windows.UI.Xaml.Documents.IRun";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IRunStatics> = L"Windows.UI.Xaml.Documents.IRunStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::ISpan> = L"Windows.UI.Xaml.Documents.ISpan";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::ISpanFactory> = L"Windows.UI.Xaml.Documents.ISpanFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::ITextElement> = L"Windows.UI.Xaml.Documents.ITextElement";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::ITextElement2> = L"Windows.UI.Xaml.Documents.ITextElement2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::ITextElement3> = L"Windows.UI.Xaml.Documents.ITextElement3";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::ITextElement4> = L"Windows.UI.Xaml.Documents.ITextElement4";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::ITextElement5> = L"Windows.UI.Xaml.Documents.ITextElement5";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::ITextElementFactory> = L"Windows.UI.Xaml.Documents.ITextElementFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::ITextElementOverrides> = L"Windows.UI.Xaml.Documents.ITextElementOverrides";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::ITextElementStatics> = L"Windows.UI.Xaml.Documents.ITextElementStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::ITextElementStatics2> = L"Windows.UI.Xaml.Documents.ITextElementStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::ITextElementStatics3> = L"Windows.UI.Xaml.Documents.ITextElementStatics3";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::ITextElementStatics4> = L"Windows.UI.Xaml.Documents.ITextElementStatics4";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::ITextHighlighter> = L"Windows.UI.Xaml.Documents.ITextHighlighter";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::ITextHighlighterBase> = L"Windows.UI.Xaml.Documents.ITextHighlighterBase";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::ITextHighlighterBaseFactory> = L"Windows.UI.Xaml.Documents.ITextHighlighterBaseFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::ITextHighlighterFactory> = L"Windows.UI.Xaml.Documents.ITextHighlighterFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::ITextHighlighterStatics> = L"Windows.UI.Xaml.Documents.ITextHighlighterStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::ITextPointer> = L"Windows.UI.Xaml.Documents.ITextPointer";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::ITypography> = L"Windows.UI.Xaml.Documents.ITypography";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::ITypographyStatics> = L"Windows.UI.Xaml.Documents.ITypographyStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::Xaml::Documents::IUnderline> = L"Windows.UI.Xaml.Documents.IUnderline";
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IBlock>{ 0x4BCE0016,0xDD47,0x4350,{ 0x8C,0xB0,0xE1,0x71,0x60,0x0A,0xC8,0x96 } }; // 4BCE0016-DD47-4350-8CB0-E171600AC896
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IBlock2>{ 0x5EC7BDF3,0x1333,0x4A92,{ 0x83,0x18,0x6C,0xAE,0xDC,0x12,0xEF,0x89 } }; // 5EC7BDF3-1333-4A92-8318-6CAEDC12EF89
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IBlockFactory>{ 0x07110532,0x4F59,0x4F3B,{ 0x9C,0xE5,0x25,0x78,0x4C,0x43,0x05,0x07 } }; // 07110532-4F59-4F3B-9CE5-25784C430507
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IBlockStatics>{ 0xF86A8C34,0x8D18,0x4C53,{ 0xAE,0xBD,0x91,0xE6,0x10,0xA5,0xE0,0x10 } }; // F86A8C34-8D18-4C53-AEBD-91E610A5E010
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IBlockStatics2>{ 0xAF01A4D6,0x03E3,0x4CEE,{ 0x9B,0x02,0x2B,0xFC,0x30,0x8B,0x27,0xA9 } }; // AF01A4D6-03E3-4CEE-9B02-2BFC308B27A9
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IBold>{ 0xADE73784,0x1B59,0x4DA4,{ 0xBB,0x23,0x0F,0x20,0xE8,0x85,0xB4,0xBF } }; // ADE73784-1B59-4DA4-BB23-0F20E885B4BF
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IContactContentLinkProvider>{ 0xF92FD29B,0x589B,0x4ABD,{ 0x9D,0x37,0x35,0xA1,0x46,0x8F,0x02,0x1E } }; // F92FD29B-589B-4ABD-9D37-35A1468F021E
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IContentLink>{ 0x6C60C3E1,0x528C,0x42F8,{ 0x92,0xBE,0x34,0xB8,0xC6,0x8B,0xE3,0x04 } }; // 6C60C3E1-528C-42F8-92BE-34B8C68BE304
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IContentLinkInvokedEventArgs>{ 0x546717C1,0xE8DF,0x4593,{ 0x96,0x39,0x97,0x59,0x5F,0xDF,0x83,0x10 } }; // 546717C1-E8DF-4593-9639-97595FDF8310
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IContentLinkProvider>{ 0x730587FD,0xBFDC,0x4CB3,{ 0x90,0x4D,0xB6,0x5A,0xB3,0x39,0xBB,0xF5 } }; // 730587FD-BFDC-4CB3-904D-B65AB339BBF5
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IContentLinkProviderCollection>{ 0xF5B84D0C,0xA9F4,0x4D1A,{ 0xA1,0x3C,0x10,0xDE,0xF1,0x84,0x37,0x34 } }; // F5B84D0C-A9F4-4D1A-A13C-10DEF1843734
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IContentLinkProviderFactory>{ 0x57D60D3B,0xEF1A,0x4E8E,{ 0x83,0x9B,0xD3,0x6E,0xF3,0xA5,0x03,0xE0 } }; // 57D60D3B-EF1A-4E8E-839B-D36EF3A503E0
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IContentLinkStatics>{ 0xA34E3063,0xEB16,0x484E,{ 0xA3,0xDF,0x52,0x2B,0x9A,0x83,0x2E,0x6E } }; // A34E3063-EB16-484E-A3DF-522B9A832E6E
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IGlyphs>{ 0xD079498B,0xF2B1,0x4281,{ 0x99,0xA2,0xE4,0xD0,0x59,0x32,0xB2,0xB5 } }; // D079498B-F2B1-4281-99A2-E4D05932B2B5
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IGlyphs2>{ 0xAA8BFE5C,0x3754,0x4BEE,{ 0xBB,0xE1,0x44,0x03,0xEE,0x9B,0x86,0xF0 } }; // AA8BFE5C-3754-4BEE-BBE1-4403EE9B86F0
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IGlyphsStatics>{ 0x225CF4C5,0xFDF1,0x43ED,{ 0x95,0x8F,0x41,0x4E,0x86,0xF1,0x03,0xF2 } }; // 225CF4C5-FDF1-43ED-958F-414E86F103F2
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IGlyphsStatics2>{ 0x10489AA7,0x1615,0x4A33,{ 0xAA,0x02,0xD7,0xEF,0x2A,0xEF,0xC7,0x39 } }; // 10489AA7-1615-4A33-AA02-D7EF2AEFC739
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IHyperlink>{ 0x0FE2363B,0x14E9,0x4152,{ 0x9E,0x58,0x5A,0xEA,0x5B,0x21,0xF0,0x8D } }; // 0FE2363B-14E9-4152-9E58-5AEA5B21F08D
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IHyperlink2>{ 0x4CE9DA5F,0x7CFF,0x4291,{ 0xB7,0x8F,0xDF,0xEC,0x72,0x49,0x05,0x76 } }; // 4CE9DA5F-7CFF-4291-B78F-DFEC72490576
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IHyperlink3>{ 0xC3F157D9,0xE5D3,0x4FB7,{ 0x87,0x02,0x4F,0x6D,0x85,0xDD,0x9E,0x0A } }; // C3F157D9-E5D3-4FB7-8702-4F6D85DD9E0A
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IHyperlink4>{ 0xF7D02959,0x82FB,0x400A,{ 0xA4,0x07,0x5A,0x4E,0xE6,0x77,0x98,0x8A } }; // F7D02959-82FB-400A-A407-5A4EE677988A
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IHyperlink5>{ 0x607DD7D2,0x0945,0x4328,{ 0x91,0xEE,0x94,0xCC,0xEC,0x2E,0xA6,0xC3 } }; // 607DD7D2-0945-4328-91EE-94CCEC2EA6C3
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IHyperlinkClickEventArgs>{ 0xC755916B,0x7BDC,0x4BE7,{ 0xB3,0x73,0x92,0x40,0xA5,0x03,0xD8,0x70 } }; // C755916B-7BDC-4BE7-B373-9240A503D870
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics>{ 0x3A44D3D4,0xFD41,0x41DB,{ 0x8C,0x72,0x3B,0x79,0x0A,0xCD,0x9F,0xD3 } }; // 3A44D3D4-FD41-41DB-8C72-3B790ACD9FD3
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics2>{ 0x5028D8B7,0x7ADF,0x43EE,{ 0xA4,0xAE,0x9C,0x92,0x5F,0x75,0x57,0x16 } }; // 5028D8B7-7ADF-43EE-A4AE-9C925F755716
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics3>{ 0x3E15DEA0,0x205E,0x4947,{ 0x99,0xA5,0x74,0xE7,0x57,0xE8,0xE1,0xB4 } }; // 3E15DEA0-205E-4947-99A5-74E757E8E1B4
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics4>{ 0x0476B378,0x8FAA,0x4E24,{ 0xB3,0xB6,0xE9,0xDE,0x4D,0x3C,0x70,0x8C } }; // 0476B378-8FAA-4E24-B3B6-E9DE4D3C708C
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics5>{ 0x59308CEA,0x1E49,0x4921,{ 0xBD,0x88,0xA2,0x87,0x8D,0x07,0xE3,0x0E } }; // 59308CEA-1E49-4921-BD88-A2878D07E30E
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IInline>{ 0x0C92712D,0x1BC9,0x4931,{ 0x8C,0xB1,0x1A,0xEA,0xDF,0x1C,0xC6,0x85 } }; // 0C92712D-1BC9-4931-8CB1-1AEADF1CC685
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IInlineFactory>{ 0x4058ACD1,0x2F90,0x4B8F,{ 0x99,0xDD,0x42,0x18,0xEF,0x5F,0x03,0xDE } }; // 4058ACD1-2F90-4B8F-99DD-4218EF5F03DE
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IInlineUIContainer>{ 0x1416CE81,0x28EE,0x452E,{ 0xB1,0x21,0x5F,0xC4,0xF6,0x0B,0x86,0xA6 } }; // 1416CE81-28EE-452E-B121-5FC4F60B86A6
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IItalic>{ 0x91F4619C,0xFCBB,0x4157,{ 0x80,0x2C,0x76,0xF6,0x3B,0x5F,0xB6,0x57 } }; // 91F4619C-FCBB-4157-802C-76F63B5FB657
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::ILineBreak>{ 0x645589C4,0xF769,0x41ED,{ 0x89,0x5B,0x8A,0x1B,0x2F,0xB3,0x15,0x62 } }; // 645589C4-F769-41ED-895B-8A1B2FB31562
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IParagraph>{ 0xF83EF59A,0xFA61,0x4BEF,{ 0xAE,0x33,0x0B,0x0A,0xD7,0x56,0xA8,0x4D } }; // F83EF59A-FA61-4BEF-AE33-0B0AD756A84D
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IParagraphStatics>{ 0xEF08889A,0x535B,0x4E4C,{ 0x8D,0x84,0x28,0x3B,0x33,0xE9,0x8A,0x37 } }; // EF08889A-535B-4E4C-8D84-283B33E98A37
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IPlaceContentLinkProvider>{ 0x10348A4C,0x2366,0x41BE,{ 0x90,0xC8,0x32,0x58,0xB5,0x3B,0x54,0x83 } }; // 10348A4C-2366-41BE-90C8-3258B53B5483
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IRun>{ 0x59553C83,0x0E14,0x49BD,{ 0xB8,0x4B,0xC5,0x26,0xF3,0x03,0x43,0x49 } }; // 59553C83-0E14-49BD-B84B-C526F3034349
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IRunStatics>{ 0xE9303CEF,0x65A0,0x4B8D,{ 0xA7,0xF7,0x8F,0xDB,0x28,0x7B,0x46,0xF3 } }; // E9303CEF-65A0-4B8D-A7F7-8FDB287B46F3
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::ISpan>{ 0x9839D4A9,0x02AF,0x4811,{ 0xAA,0x15,0x6B,0xEF,0x3A,0xCA,0xC9,0x7A } }; // 9839D4A9-02AF-4811-AA15-6BEF3ACAC97A
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::ISpanFactory>{ 0x5B916F5C,0xCD2D,0x40C0,{ 0x95,0x6A,0x38,0x64,0x48,0x32,0x2F,0x79 } }; // 5B916F5C-CD2D-40C0-956A-386448322F79
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::ITextElement>{ 0xE83B0062,0xD776,0x4F92,{ 0xBA,0xEA,0x40,0xE7,0x7D,0x47,0x91,0xD5 } }; // E83B0062-D776-4F92-BAEA-40E77D4791D5
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::ITextElement2>{ 0xA8076AA8,0xF892,0x49F6,{ 0x8C,0xD2,0x89,0xAD,0xDA,0xF0,0x6D,0x2D } }; // A8076AA8-F892-49F6-8CD2-89ADDAF06D2D
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::ITextElement3>{ 0xD1DB340F,0x1BC4,0x4CA8,{ 0xBC,0xF7,0x77,0x0B,0xFF,0x9B,0x27,0xAB } }; // D1DB340F-1BC4-4CA8-BCF7-770BFF9B27AB
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::ITextElement4>{ 0xB196E222,0xCA0E,0x48A9,{ 0x83,0xBC,0x36,0xCE,0x50,0x56,0x6A,0xC7 } }; // B196E222-CA0E-48A9-83BC-36CE50566AC7
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::ITextElement5>{ 0xBD9552F3,0x540D,0x58BF,{ 0xB6,0xA8,0x07,0x55,0x6A,0xED,0xA2,0xEA } }; // BD9552F3-540D-58BF-B6A8-07556AEDA2EA
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::ITextElementFactory>{ 0x35007285,0xCF47,0x4BFE,{ 0xB1,0xBC,0x39,0xC9,0x3A,0xF4,0xAE,0x80 } }; // 35007285-CF47-4BFE-B1BC-39C93AF4AE80
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::ITextElementOverrides>{ 0x0CE21EE7,0x4F76,0x4DD9,{ 0xBF,0x91,0x16,0x3B,0xEC,0xCF,0x84,0xBC } }; // 0CE21EE7-4F76-4DD9-BF91-163BECCF84BC
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::ITextElementStatics>{ 0x0A2F9B98,0x6C03,0x4470,{ 0xA7,0x9B,0x32,0x98,0xA1,0x04,0x82,0xCE } }; // 0A2F9B98-6C03-4470-A79B-3298A10482CE
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::ITextElementStatics2>{ 0x164297B2,0x982B,0x49E1,{ 0x8C,0x03,0xCA,0x43,0xBC,0x4D,0x5B,0x6D } }; // 164297B2-982B-49E1-8C03-CA43BC4D5B6D
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::ITextElementStatics3>{ 0xCFEFCFAF,0x0FA1,0x45EC,{ 0x9A,0x4E,0x9B,0x33,0x66,0x4D,0xC8,0xB1 } }; // CFEFCFAF-0FA1-45EC-9A4E-9B33664DC8B1
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::ITextElementStatics4>{ 0xFD8F641E,0x6B12,0x40D5,{ 0xB6,0xEF,0xD1,0xBD,0x12,0xAC,0x90,0x66 } }; // FD8F641E-6B12-40D5-B6EF-D1BD12AC9066
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::ITextHighlighter>{ 0xBA6CB54B,0x7D75,0x4535,{ 0xB3,0x0D,0xA8,0x1A,0x00,0xB6,0x37,0xA4 } }; // BA6CB54B-7D75-4535-B30D-A81A00B637A4
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::ITextHighlighterBase>{ 0xD957601A,0x5F0D,0x4CDF,{ 0x97,0x58,0x97,0xE0,0xEB,0x95,0xC8,0xFA } }; // D957601A-5F0D-4CDF-9758-97E0EB95C8FA
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::ITextHighlighterBaseFactory>{ 0x9592B2D0,0xEADC,0x4C74,{ 0x92,0xC8,0x6E,0x89,0x6E,0x22,0x50,0x6D } }; // 9592B2D0-EADC-4C74-92C8-6E896E22506D
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::ITextHighlighterFactory>{ 0x70125461,0x9A8F,0x4FA0,{ 0xB2,0x35,0x8F,0xFA,0xA5,0x07,0xBE,0xF2 } }; // 70125461-9A8F-4FA0-B235-8FFAA507BEF2
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::ITextHighlighterStatics>{ 0xB3B009C4,0x3A7E,0x49CC,{ 0xAB,0x84,0x29,0xC4,0x05,0x48,0x87,0x65 } }; // B3B009C4-3A7E-49CC-AB84-29C405488765
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::ITextPointer>{ 0xAC687AA1,0x6A41,0x43FF,{ 0x85,0x1E,0x45,0x34,0x8A,0xA2,0xCF,0x7B } }; // AC687AA1-6A41-43FF-851E-45348AA2CF7B
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::ITypography>{ 0x866F65D5,0xEA97,0x42AB,{ 0x92,0x88,0x9C,0x01,0xAE,0xBC,0x7A,0x97 } }; // 866F65D5-EA97-42AB-9288-9C01AEBC7A97
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::ITypographyStatics>{ 0x67B9EC88,0x6C57,0x4CE0,{ 0x95,0xF1,0xD4,0xB9,0xED,0x63,0x2F,0xB4 } }; // 67B9EC88-6C57-4CE0-95F1-D4B9ED632FB4
    template <> inline constexpr guid guid_v<winrt::Windows::UI::Xaml::Documents::IUnderline>{ 0xA5FA8202,0x61C0,0x47D7,{ 0x93,0xEF,0xBC,0x0B,0x57,0x7C,0x5F,0x26 } }; // A5FA8202-61C0-47D7-93EF-BC0B577C5F26
    template <> struct default_interface<winrt::Windows::UI::Xaml::Documents::Block>{ using type = winrt::Windows::UI::Xaml::Documents::IBlock; };
    template <> struct default_interface<winrt::Windows::UI::Xaml::Documents::BlockCollection>{ using type = winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Documents::Block>; };
    template <> struct default_interface<winrt::Windows::UI::Xaml::Documents::Bold>{ using type = winrt::Windows::UI::Xaml::Documents::IBold; };
    template <> struct default_interface<winrt::Windows::UI::Xaml::Documents::ContactContentLinkProvider>{ using type = winrt::Windows::UI::Xaml::Documents::IContactContentLinkProvider; };
    template <> struct default_interface<winrt::Windows::UI::Xaml::Documents::ContentLink>{ using type = winrt::Windows::UI::Xaml::Documents::IContentLink; };
    template <> struct default_interface<winrt::Windows::UI::Xaml::Documents::ContentLinkInvokedEventArgs>{ using type = winrt::Windows::UI::Xaml::Documents::IContentLinkInvokedEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::Xaml::Documents::ContentLinkProvider>{ using type = winrt::Windows::UI::Xaml::Documents::IContentLinkProvider; };
    template <> struct default_interface<winrt::Windows::UI::Xaml::Documents::ContentLinkProviderCollection>{ using type = winrt::Windows::UI::Xaml::Documents::IContentLinkProviderCollection; };
    template <> struct default_interface<winrt::Windows::UI::Xaml::Documents::Glyphs>{ using type = winrt::Windows::UI::Xaml::Documents::IGlyphs; };
    template <> struct default_interface<winrt::Windows::UI::Xaml::Documents::Hyperlink>{ using type = winrt::Windows::UI::Xaml::Documents::IHyperlink; };
    template <> struct default_interface<winrt::Windows::UI::Xaml::Documents::HyperlinkClickEventArgs>{ using type = winrt::Windows::UI::Xaml::Documents::IHyperlinkClickEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::Xaml::Documents::Inline>{ using type = winrt::Windows::UI::Xaml::Documents::IInline; };
    template <> struct default_interface<winrt::Windows::UI::Xaml::Documents::InlineCollection>{ using type = winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Documents::Inline>; };
    template <> struct default_interface<winrt::Windows::UI::Xaml::Documents::InlineUIContainer>{ using type = winrt::Windows::UI::Xaml::Documents::IInlineUIContainer; };
    template <> struct default_interface<winrt::Windows::UI::Xaml::Documents::Italic>{ using type = winrt::Windows::UI::Xaml::Documents::IItalic; };
    template <> struct default_interface<winrt::Windows::UI::Xaml::Documents::LineBreak>{ using type = winrt::Windows::UI::Xaml::Documents::ILineBreak; };
    template <> struct default_interface<winrt::Windows::UI::Xaml::Documents::Paragraph>{ using type = winrt::Windows::UI::Xaml::Documents::IParagraph; };
    template <> struct default_interface<winrt::Windows::UI::Xaml::Documents::PlaceContentLinkProvider>{ using type = winrt::Windows::UI::Xaml::Documents::IPlaceContentLinkProvider; };
    template <> struct default_interface<winrt::Windows::UI::Xaml::Documents::Run>{ using type = winrt::Windows::UI::Xaml::Documents::IRun; };
    template <> struct default_interface<winrt::Windows::UI::Xaml::Documents::Span>{ using type = winrt::Windows::UI::Xaml::Documents::ISpan; };
    template <> struct default_interface<winrt::Windows::UI::Xaml::Documents::TextElement>{ using type = winrt::Windows::UI::Xaml::Documents::ITextElement; };
    template <> struct default_interface<winrt::Windows::UI::Xaml::Documents::TextHighlighter>{ using type = winrt::Windows::UI::Xaml::Documents::ITextHighlighter; };
    template <> struct default_interface<winrt::Windows::UI::Xaml::Documents::TextHighlighterBase>{ using type = winrt::Windows::UI::Xaml::Documents::ITextHighlighterBase; };
    template <> struct default_interface<winrt::Windows::UI::Xaml::Documents::TextPointer>{ using type = winrt::Windows::UI::Xaml::Documents::ITextPointer; };
    template <> struct default_interface<winrt::Windows::UI::Xaml::Documents::Typography>{ using type = winrt::Windows::UI::Xaml::Documents::ITypography; };
    template <> struct default_interface<winrt::Windows::UI::Xaml::Documents::Underline>{ using type = winrt::Windows::UI::Xaml::Documents::IUnderline; };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IBlock>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_TextAlignment(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_TextAlignment(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_LineHeight(double*) noexcept = 0;
            virtual int32_t __stdcall put_LineHeight(double) noexcept = 0;
            virtual int32_t __stdcall get_LineStackingStrategy(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_LineStackingStrategy(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_Margin(struct struct_Windows_UI_Xaml_Thickness*) noexcept = 0;
            virtual int32_t __stdcall put_Margin(struct struct_Windows_UI_Xaml_Thickness) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IBlock2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_HorizontalTextAlignment(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_HorizontalTextAlignment(int32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IBlockFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateInstance(void*, void**, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IBlockStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_TextAlignmentProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_LineHeightProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_LineStackingStrategyProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_MarginProperty(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IBlockStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_HorizontalTextAlignmentProperty(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IBold>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IContactContentLinkProvider>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IContentLink>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Info(void**) noexcept = 0;
            virtual int32_t __stdcall put_Info(void*) noexcept = 0;
            virtual int32_t __stdcall get_Background(void**) noexcept = 0;
            virtual int32_t __stdcall put_Background(void*) noexcept = 0;
            virtual int32_t __stdcall get_Cursor(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_Cursor(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusLeft(void**) noexcept = 0;
            virtual int32_t __stdcall put_XYFocusLeft(void*) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusRight(void**) noexcept = 0;
            virtual int32_t __stdcall put_XYFocusRight(void*) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusUp(void**) noexcept = 0;
            virtual int32_t __stdcall put_XYFocusUp(void*) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusDown(void**) noexcept = 0;
            virtual int32_t __stdcall put_XYFocusDown(void*) noexcept = 0;
            virtual int32_t __stdcall get_ElementSoundMode(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ElementSoundMode(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_FocusState(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusUpNavigationStrategy(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_XYFocusUpNavigationStrategy(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusDownNavigationStrategy(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_XYFocusDownNavigationStrategy(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusLeftNavigationStrategy(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_XYFocusLeftNavigationStrategy(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusRightNavigationStrategy(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_XYFocusRightNavigationStrategy(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_IsTabStop(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsTabStop(bool) noexcept = 0;
            virtual int32_t __stdcall get_TabIndex(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_TabIndex(int32_t) noexcept = 0;
            virtual int32_t __stdcall add_Invoked(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Invoked(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_GotFocus(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_GotFocus(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_LostFocus(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_LostFocus(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall Focus(int32_t, bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IContentLinkInvokedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ContentLinkInfo(void**) noexcept = 0;
            virtual int32_t __stdcall get_Handled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_Handled(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IContentLinkProvider>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IContentLinkProviderCollection>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IContentLinkProviderFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateInstance(void*, void**, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IContentLinkStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_BackgroundProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_CursorProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusLeftProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusRightProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusUpProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusDownProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_ElementSoundModeProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_FocusStateProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusUpNavigationStrategyProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusDownNavigationStrategyProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusLeftNavigationStrategyProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusRightNavigationStrategyProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_IsTabStopProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_TabIndexProperty(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IGlyphs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_UnicodeString(void**) noexcept = 0;
            virtual int32_t __stdcall put_UnicodeString(void*) noexcept = 0;
            virtual int32_t __stdcall get_Indices(void**) noexcept = 0;
            virtual int32_t __stdcall put_Indices(void*) noexcept = 0;
            virtual int32_t __stdcall get_FontUri(void**) noexcept = 0;
            virtual int32_t __stdcall put_FontUri(void*) noexcept = 0;
            virtual int32_t __stdcall get_StyleSimulations(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_StyleSimulations(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_FontRenderingEmSize(double*) noexcept = 0;
            virtual int32_t __stdcall put_FontRenderingEmSize(double) noexcept = 0;
            virtual int32_t __stdcall get_OriginX(double*) noexcept = 0;
            virtual int32_t __stdcall put_OriginX(double) noexcept = 0;
            virtual int32_t __stdcall get_OriginY(double*) noexcept = 0;
            virtual int32_t __stdcall put_OriginY(double) noexcept = 0;
            virtual int32_t __stdcall get_Fill(void**) noexcept = 0;
            virtual int32_t __stdcall put_Fill(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IGlyphs2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsColorFontEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsColorFontEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall get_ColorFontPaletteIndex(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ColorFontPaletteIndex(int32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IGlyphsStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_UnicodeStringProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_IndicesProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_FontUriProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_StyleSimulationsProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_FontRenderingEmSizeProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_OriginXProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_OriginYProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_FillProperty(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IGlyphsStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsColorFontEnabledProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_ColorFontPaletteIndexProperty(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IHyperlink>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_NavigateUri(void**) noexcept = 0;
            virtual int32_t __stdcall put_NavigateUri(void*) noexcept = 0;
            virtual int32_t __stdcall add_Click(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Click(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IHyperlink2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_UnderlineStyle(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_UnderlineStyle(int32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IHyperlink3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_XYFocusLeft(void**) noexcept = 0;
            virtual int32_t __stdcall put_XYFocusLeft(void*) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusRight(void**) noexcept = 0;
            virtual int32_t __stdcall put_XYFocusRight(void*) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusUp(void**) noexcept = 0;
            virtual int32_t __stdcall put_XYFocusUp(void*) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusDown(void**) noexcept = 0;
            virtual int32_t __stdcall put_XYFocusDown(void*) noexcept = 0;
            virtual int32_t __stdcall get_ElementSoundMode(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ElementSoundMode(int32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IHyperlink4>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_FocusState(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusUpNavigationStrategy(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_XYFocusUpNavigationStrategy(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusDownNavigationStrategy(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_XYFocusDownNavigationStrategy(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusLeftNavigationStrategy(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_XYFocusLeftNavigationStrategy(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusRightNavigationStrategy(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_XYFocusRightNavigationStrategy(int32_t) noexcept = 0;
            virtual int32_t __stdcall add_GotFocus(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_GotFocus(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_LostFocus(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_LostFocus(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall Focus(int32_t, bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IHyperlink5>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsTabStop(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsTabStop(bool) noexcept = 0;
            virtual int32_t __stdcall get_TabIndex(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_TabIndex(int32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IHyperlinkClickEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_NavigateUriProperty(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_UnderlineStyleProperty(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_XYFocusLeftProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusRightProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusUpProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusDownProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_ElementSoundModeProperty(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics4>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_FocusStateProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusUpNavigationStrategyProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusDownNavigationStrategyProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusLeftNavigationStrategyProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_XYFocusRightNavigationStrategyProperty(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics5>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsTabStopProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_TabIndexProperty(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IInline>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IInlineFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateInstance(void*, void**, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IInlineUIContainer>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Child(void**) noexcept = 0;
            virtual int32_t __stdcall put_Child(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IItalic>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::ILineBreak>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IParagraph>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Inlines(void**) noexcept = 0;
            virtual int32_t __stdcall get_TextIndent(double*) noexcept = 0;
            virtual int32_t __stdcall put_TextIndent(double) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IParagraphStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_TextIndentProperty(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IPlaceContentLinkProvider>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IRun>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Text(void**) noexcept = 0;
            virtual int32_t __stdcall put_Text(void*) noexcept = 0;
            virtual int32_t __stdcall get_FlowDirection(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_FlowDirection(int32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IRunStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_FlowDirectionProperty(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::ISpan>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Inlines(void**) noexcept = 0;
            virtual int32_t __stdcall put_Inlines(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::ISpanFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateInstance(void*, void**, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::ITextElement>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Name(void**) noexcept = 0;
            virtual int32_t __stdcall get_FontSize(double*) noexcept = 0;
            virtual int32_t __stdcall put_FontSize(double) noexcept = 0;
            virtual int32_t __stdcall get_FontFamily(void**) noexcept = 0;
            virtual int32_t __stdcall put_FontFamily(void*) noexcept = 0;
            virtual int32_t __stdcall get_FontWeight(struct struct_Windows_UI_Text_FontWeight*) noexcept = 0;
            virtual int32_t __stdcall put_FontWeight(struct struct_Windows_UI_Text_FontWeight) noexcept = 0;
            virtual int32_t __stdcall get_FontStyle(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_FontStyle(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_FontStretch(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_FontStretch(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_CharacterSpacing(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_CharacterSpacing(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_Foreground(void**) noexcept = 0;
            virtual int32_t __stdcall put_Foreground(void*) noexcept = 0;
            virtual int32_t __stdcall get_Language(void**) noexcept = 0;
            virtual int32_t __stdcall put_Language(void*) noexcept = 0;
            virtual int32_t __stdcall get_ContentStart(void**) noexcept = 0;
            virtual int32_t __stdcall get_ContentEnd(void**) noexcept = 0;
            virtual int32_t __stdcall get_ElementStart(void**) noexcept = 0;
            virtual int32_t __stdcall get_ElementEnd(void**) noexcept = 0;
            virtual int32_t __stdcall FindName(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::ITextElement2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsTextScaleFactorEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsTextScaleFactorEnabled(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::ITextElement3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AllowFocusOnInteraction(bool*) noexcept = 0;
            virtual int32_t __stdcall put_AllowFocusOnInteraction(bool) noexcept = 0;
            virtual int32_t __stdcall get_AccessKey(void**) noexcept = 0;
            virtual int32_t __stdcall put_AccessKey(void*) noexcept = 0;
            virtual int32_t __stdcall get_ExitDisplayModeOnAccessKeyInvoked(bool*) noexcept = 0;
            virtual int32_t __stdcall put_ExitDisplayModeOnAccessKeyInvoked(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::ITextElement4>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_TextDecorations(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_TextDecorations(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_IsAccessKeyScope(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsAccessKeyScope(bool) noexcept = 0;
            virtual int32_t __stdcall get_AccessKeyScopeOwner(void**) noexcept = 0;
            virtual int32_t __stdcall put_AccessKeyScopeOwner(void*) noexcept = 0;
            virtual int32_t __stdcall get_KeyTipPlacementMode(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_KeyTipPlacementMode(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_KeyTipHorizontalOffset(double*) noexcept = 0;
            virtual int32_t __stdcall put_KeyTipHorizontalOffset(double) noexcept = 0;
            virtual int32_t __stdcall get_KeyTipVerticalOffset(double*) noexcept = 0;
            virtual int32_t __stdcall put_KeyTipVerticalOffset(double) noexcept = 0;
            virtual int32_t __stdcall add_AccessKeyDisplayRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_AccessKeyDisplayRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_AccessKeyDisplayDismissed(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_AccessKeyDisplayDismissed(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_AccessKeyInvoked(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_AccessKeyInvoked(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::ITextElement5>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_XamlRoot(void**) noexcept = 0;
            virtual int32_t __stdcall put_XamlRoot(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::ITextElementFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::ITextElementOverrides>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall OnDisconnectVisualChildren() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::ITextElementStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_FontSizeProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_FontFamilyProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_FontWeightProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_FontStyleProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_FontStretchProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_CharacterSpacingProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_ForegroundProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_LanguageProperty(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::ITextElementStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsTextScaleFactorEnabledProperty(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::ITextElementStatics3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AllowFocusOnInteractionProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_AccessKeyProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_ExitDisplayModeOnAccessKeyInvokedProperty(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::ITextElementStatics4>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_TextDecorationsProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_IsAccessKeyScopeProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_AccessKeyScopeOwnerProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_KeyTipPlacementModeProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_KeyTipHorizontalOffsetProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_KeyTipVerticalOffsetProperty(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::ITextHighlighter>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Ranges(void**) noexcept = 0;
            virtual int32_t __stdcall get_Foreground(void**) noexcept = 0;
            virtual int32_t __stdcall put_Foreground(void*) noexcept = 0;
            virtual int32_t __stdcall get_Background(void**) noexcept = 0;
            virtual int32_t __stdcall put_Background(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::ITextHighlighterBase>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::ITextHighlighterBaseFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::ITextHighlighterFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateInstance(void*, void**, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::ITextHighlighterStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ForegroundProperty(void**) noexcept = 0;
            virtual int32_t __stdcall get_BackgroundProperty(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::ITextPointer>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Parent(void**) noexcept = 0;
            virtual int32_t __stdcall get_VisualParent(void**) noexcept = 0;
            virtual int32_t __stdcall get_LogicalDirection(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Offset(int32_t*) noexcept = 0;
            virtual int32_t __stdcall GetCharacterRect(int32_t, winrt::Windows::Foundation::Rect*) noexcept = 0;
            virtual int32_t __stdcall GetPositionAtOffset(int32_t, int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::ITypography>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::ITypographyStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AnnotationAlternatesProperty(void**) noexcept = 0;
            virtual int32_t __stdcall GetAnnotationAlternates(void*, int32_t*) noexcept = 0;
            virtual int32_t __stdcall SetAnnotationAlternates(void*, int32_t) noexcept = 0;
            virtual int32_t __stdcall get_EastAsianExpertFormsProperty(void**) noexcept = 0;
            virtual int32_t __stdcall GetEastAsianExpertForms(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetEastAsianExpertForms(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_EastAsianLanguageProperty(void**) noexcept = 0;
            virtual int32_t __stdcall GetEastAsianLanguage(void*, int32_t*) noexcept = 0;
            virtual int32_t __stdcall SetEastAsianLanguage(void*, int32_t) noexcept = 0;
            virtual int32_t __stdcall get_EastAsianWidthsProperty(void**) noexcept = 0;
            virtual int32_t __stdcall GetEastAsianWidths(void*, int32_t*) noexcept = 0;
            virtual int32_t __stdcall SetEastAsianWidths(void*, int32_t) noexcept = 0;
            virtual int32_t __stdcall get_StandardLigaturesProperty(void**) noexcept = 0;
            virtual int32_t __stdcall GetStandardLigatures(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetStandardLigatures(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_ContextualLigaturesProperty(void**) noexcept = 0;
            virtual int32_t __stdcall GetContextualLigatures(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetContextualLigatures(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_DiscretionaryLigaturesProperty(void**) noexcept = 0;
            virtual int32_t __stdcall GetDiscretionaryLigatures(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetDiscretionaryLigatures(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_HistoricalLigaturesProperty(void**) noexcept = 0;
            virtual int32_t __stdcall GetHistoricalLigatures(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetHistoricalLigatures(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_StandardSwashesProperty(void**) noexcept = 0;
            virtual int32_t __stdcall GetStandardSwashes(void*, int32_t*) noexcept = 0;
            virtual int32_t __stdcall SetStandardSwashes(void*, int32_t) noexcept = 0;
            virtual int32_t __stdcall get_ContextualSwashesProperty(void**) noexcept = 0;
            virtual int32_t __stdcall GetContextualSwashes(void*, int32_t*) noexcept = 0;
            virtual int32_t __stdcall SetContextualSwashes(void*, int32_t) noexcept = 0;
            virtual int32_t __stdcall get_ContextualAlternatesProperty(void**) noexcept = 0;
            virtual int32_t __stdcall GetContextualAlternates(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetContextualAlternates(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_StylisticAlternatesProperty(void**) noexcept = 0;
            virtual int32_t __stdcall GetStylisticAlternates(void*, int32_t*) noexcept = 0;
            virtual int32_t __stdcall SetStylisticAlternates(void*, int32_t) noexcept = 0;
            virtual int32_t __stdcall get_StylisticSet1Property(void**) noexcept = 0;
            virtual int32_t __stdcall GetStylisticSet1(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetStylisticSet1(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_StylisticSet2Property(void**) noexcept = 0;
            virtual int32_t __stdcall GetStylisticSet2(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetStylisticSet2(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_StylisticSet3Property(void**) noexcept = 0;
            virtual int32_t __stdcall GetStylisticSet3(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetStylisticSet3(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_StylisticSet4Property(void**) noexcept = 0;
            virtual int32_t __stdcall GetStylisticSet4(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetStylisticSet4(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_StylisticSet5Property(void**) noexcept = 0;
            virtual int32_t __stdcall GetStylisticSet5(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetStylisticSet5(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_StylisticSet6Property(void**) noexcept = 0;
            virtual int32_t __stdcall GetStylisticSet6(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetStylisticSet6(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_StylisticSet7Property(void**) noexcept = 0;
            virtual int32_t __stdcall GetStylisticSet7(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetStylisticSet7(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_StylisticSet8Property(void**) noexcept = 0;
            virtual int32_t __stdcall GetStylisticSet8(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetStylisticSet8(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_StylisticSet9Property(void**) noexcept = 0;
            virtual int32_t __stdcall GetStylisticSet9(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetStylisticSet9(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_StylisticSet10Property(void**) noexcept = 0;
            virtual int32_t __stdcall GetStylisticSet10(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetStylisticSet10(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_StylisticSet11Property(void**) noexcept = 0;
            virtual int32_t __stdcall GetStylisticSet11(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetStylisticSet11(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_StylisticSet12Property(void**) noexcept = 0;
            virtual int32_t __stdcall GetStylisticSet12(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetStylisticSet12(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_StylisticSet13Property(void**) noexcept = 0;
            virtual int32_t __stdcall GetStylisticSet13(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetStylisticSet13(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_StylisticSet14Property(void**) noexcept = 0;
            virtual int32_t __stdcall GetStylisticSet14(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetStylisticSet14(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_StylisticSet15Property(void**) noexcept = 0;
            virtual int32_t __stdcall GetStylisticSet15(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetStylisticSet15(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_StylisticSet16Property(void**) noexcept = 0;
            virtual int32_t __stdcall GetStylisticSet16(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetStylisticSet16(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_StylisticSet17Property(void**) noexcept = 0;
            virtual int32_t __stdcall GetStylisticSet17(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetStylisticSet17(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_StylisticSet18Property(void**) noexcept = 0;
            virtual int32_t __stdcall GetStylisticSet18(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetStylisticSet18(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_StylisticSet19Property(void**) noexcept = 0;
            virtual int32_t __stdcall GetStylisticSet19(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetStylisticSet19(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_StylisticSet20Property(void**) noexcept = 0;
            virtual int32_t __stdcall GetStylisticSet20(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetStylisticSet20(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_CapitalsProperty(void**) noexcept = 0;
            virtual int32_t __stdcall GetCapitals(void*, int32_t*) noexcept = 0;
            virtual int32_t __stdcall SetCapitals(void*, int32_t) noexcept = 0;
            virtual int32_t __stdcall get_CapitalSpacingProperty(void**) noexcept = 0;
            virtual int32_t __stdcall GetCapitalSpacing(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetCapitalSpacing(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_KerningProperty(void**) noexcept = 0;
            virtual int32_t __stdcall GetKerning(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetKerning(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_CaseSensitiveFormsProperty(void**) noexcept = 0;
            virtual int32_t __stdcall GetCaseSensitiveForms(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetCaseSensitiveForms(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_HistoricalFormsProperty(void**) noexcept = 0;
            virtual int32_t __stdcall GetHistoricalForms(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetHistoricalForms(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_FractionProperty(void**) noexcept = 0;
            virtual int32_t __stdcall GetFraction(void*, int32_t*) noexcept = 0;
            virtual int32_t __stdcall SetFraction(void*, int32_t) noexcept = 0;
            virtual int32_t __stdcall get_NumeralStyleProperty(void**) noexcept = 0;
            virtual int32_t __stdcall GetNumeralStyle(void*, int32_t*) noexcept = 0;
            virtual int32_t __stdcall SetNumeralStyle(void*, int32_t) noexcept = 0;
            virtual int32_t __stdcall get_NumeralAlignmentProperty(void**) noexcept = 0;
            virtual int32_t __stdcall GetNumeralAlignment(void*, int32_t*) noexcept = 0;
            virtual int32_t __stdcall SetNumeralAlignment(void*, int32_t) noexcept = 0;
            virtual int32_t __stdcall get_SlashedZeroProperty(void**) noexcept = 0;
            virtual int32_t __stdcall GetSlashedZero(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetSlashedZero(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_MathematicalGreekProperty(void**) noexcept = 0;
            virtual int32_t __stdcall GetMathematicalGreek(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall SetMathematicalGreek(void*, bool) noexcept = 0;
            virtual int32_t __stdcall get_VariantsProperty(void**) noexcept = 0;
            virtual int32_t __stdcall GetVariants(void*, int32_t*) noexcept = 0;
            virtual int32_t __stdcall SetVariants(void*, int32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::Xaml::Documents::IUnderline>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IBlock
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::TextAlignment) TextAlignment() const;
        WINRT_IMPL_AUTO(void) TextAlignment(winrt::Windows::UI::Xaml::TextAlignment const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) LineHeight() const;
        WINRT_IMPL_AUTO(void) LineHeight(double value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::LineStackingStrategy) LineStackingStrategy() const;
        WINRT_IMPL_AUTO(void) LineStackingStrategy(winrt::Windows::UI::Xaml::LineStackingStrategy const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Thickness) Margin() const;
        WINRT_IMPL_AUTO(void) Margin(winrt::Windows::UI::Xaml::Thickness const& value) const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IBlock>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IBlock<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IBlock2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::TextAlignment) HorizontalTextAlignment() const;
        WINRT_IMPL_AUTO(void) HorizontalTextAlignment(winrt::Windows::UI::Xaml::TextAlignment const& value) const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IBlock2>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IBlock2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IBlockFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Documents::Block) CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IBlockFactory>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IBlockFactory<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IBlockStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) TextAlignmentProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) LineHeightProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) LineStackingStrategyProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) MarginProperty() const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IBlockStatics>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IBlockStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IBlockStatics2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) HorizontalTextAlignmentProperty() const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IBlockStatics2>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IBlockStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IBold
    {
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IBold>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IBold<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IContactContentLinkProvider
    {
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IContactContentLinkProvider>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IContactContentLinkProvider<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IContentLink
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Text::ContentLinkInfo) Info() const;
        WINRT_IMPL_AUTO(void) Info(winrt::Windows::UI::Text::ContentLinkInfo const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) Background() const;
        WINRT_IMPL_AUTO(void) Background(winrt::Windows::UI::Xaml::Media::Brush const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Core::CoreCursorType) Cursor() const;
        WINRT_IMPL_AUTO(void) Cursor(winrt::Windows::UI::Core::CoreCursorType const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) XYFocusLeft() const;
        WINRT_IMPL_AUTO(void) XYFocusLeft(winrt::Windows::UI::Xaml::DependencyObject const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) XYFocusRight() const;
        WINRT_IMPL_AUTO(void) XYFocusRight(winrt::Windows::UI::Xaml::DependencyObject const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) XYFocusUp() const;
        WINRT_IMPL_AUTO(void) XYFocusUp(winrt::Windows::UI::Xaml::DependencyObject const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) XYFocusDown() const;
        WINRT_IMPL_AUTO(void) XYFocusDown(winrt::Windows::UI::Xaml::DependencyObject const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::ElementSoundMode) ElementSoundMode() const;
        WINRT_IMPL_AUTO(void) ElementSoundMode(winrt::Windows::UI::Xaml::ElementSoundMode const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FocusState) FocusState() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy) XYFocusUpNavigationStrategy() const;
        WINRT_IMPL_AUTO(void) XYFocusUpNavigationStrategy(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy) XYFocusDownNavigationStrategy() const;
        WINRT_IMPL_AUTO(void) XYFocusDownNavigationStrategy(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy) XYFocusLeftNavigationStrategy() const;
        WINRT_IMPL_AUTO(void) XYFocusLeftNavigationStrategy(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy) XYFocusRightNavigationStrategy() const;
        WINRT_IMPL_AUTO(void) XYFocusRightNavigationStrategy(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsTabStop() const;
        WINRT_IMPL_AUTO(void) IsTabStop(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) TabIndex() const;
        WINRT_IMPL_AUTO(void) TabIndex(int32_t value) const;
        WINRT_IMPL_AUTO(winrt::event_token) Invoked(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Documents::ContentLink, winrt::Windows::UI::Xaml::Documents::ContentLinkInvokedEventArgs> const& handler) const;
        using Invoked_revoker = impl::event_revoker<winrt::Windows::UI::Xaml::Documents::IContentLink, &impl::abi_t<winrt::Windows::UI::Xaml::Documents::IContentLink>::remove_Invoked>;
        [[nodiscard]] Invoked_revoker Invoked(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Documents::ContentLink, winrt::Windows::UI::Xaml::Documents::ContentLinkInvokedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) Invoked(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) GotFocus(winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const;
        using GotFocus_revoker = impl::event_revoker<winrt::Windows::UI::Xaml::Documents::IContentLink, &impl::abi_t<winrt::Windows::UI::Xaml::Documents::IContentLink>::remove_GotFocus>;
        [[nodiscard]] GotFocus_revoker GotFocus(auto_revoke_t, winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const;
        WINRT_IMPL_AUTO(void) GotFocus(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) LostFocus(winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const;
        using LostFocus_revoker = impl::event_revoker<winrt::Windows::UI::Xaml::Documents::IContentLink, &impl::abi_t<winrt::Windows::UI::Xaml::Documents::IContentLink>::remove_LostFocus>;
        [[nodiscard]] LostFocus_revoker LostFocus(auto_revoke_t, winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const;
        WINRT_IMPL_AUTO(void) LostFocus(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(bool) Focus(winrt::Windows::UI::Xaml::FocusState const& value) const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IContentLink>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IContentLink<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IContentLinkInvokedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Text::ContentLinkInfo) ContentLinkInfo() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) Handled() const;
        WINRT_IMPL_AUTO(void) Handled(bool value) const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IContentLinkInvokedEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IContentLinkInvokedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IContentLinkProvider
    {
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IContentLinkProvider>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IContentLinkProvider<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IContentLinkProviderCollection
    {
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IContentLinkProviderCollection>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IContentLinkProviderCollection<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IContentLinkProviderFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Documents::ContentLinkProvider) CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IContentLinkProviderFactory>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IContentLinkProviderFactory<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IContentLinkStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) BackgroundProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) CursorProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) XYFocusLeftProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) XYFocusRightProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) XYFocusUpProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) XYFocusDownProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) ElementSoundModeProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) FocusStateProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) XYFocusUpNavigationStrategyProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) XYFocusDownNavigationStrategyProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) XYFocusLeftNavigationStrategyProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) XYFocusRightNavigationStrategyProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) IsTabStopProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) TabIndexProperty() const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IContentLinkStatics>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IContentLinkStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IGlyphs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) UnicodeString() const;
        WINRT_IMPL_AUTO(void) UnicodeString(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Indices() const;
        WINRT_IMPL_AUTO(void) Indices(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) FontUri() const;
        WINRT_IMPL_AUTO(void) FontUri(winrt::Windows::Foundation::Uri const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::StyleSimulations) StyleSimulations() const;
        WINRT_IMPL_AUTO(void) StyleSimulations(winrt::Windows::UI::Xaml::Media::StyleSimulations const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) FontRenderingEmSize() const;
        WINRT_IMPL_AUTO(void) FontRenderingEmSize(double value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) OriginX() const;
        WINRT_IMPL_AUTO(void) OriginX(double value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) OriginY() const;
        WINRT_IMPL_AUTO(void) OriginY(double value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) Fill() const;
        WINRT_IMPL_AUTO(void) Fill(winrt::Windows::UI::Xaml::Media::Brush const& value) const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IGlyphs>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IGlyphs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IGlyphs2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsColorFontEnabled() const;
        WINRT_IMPL_AUTO(void) IsColorFontEnabled(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) ColorFontPaletteIndex() const;
        WINRT_IMPL_AUTO(void) ColorFontPaletteIndex(int32_t value) const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IGlyphs2>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IGlyphs2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IGlyphsStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) UnicodeStringProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) IndicesProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) FontUriProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) StyleSimulationsProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) FontRenderingEmSizeProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) OriginXProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) OriginYProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) FillProperty() const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IGlyphsStatics>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IGlyphsStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IGlyphsStatics2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) IsColorFontEnabledProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) ColorFontPaletteIndexProperty() const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IGlyphsStatics2>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IGlyphsStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IHyperlink
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) NavigateUri() const;
        WINRT_IMPL_AUTO(void) NavigateUri(winrt::Windows::Foundation::Uri const& value) const;
        WINRT_IMPL_AUTO(winrt::event_token) Click(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Documents::Hyperlink, winrt::Windows::UI::Xaml::Documents::HyperlinkClickEventArgs> const& handler) const;
        using Click_revoker = impl::event_revoker<winrt::Windows::UI::Xaml::Documents::IHyperlink, &impl::abi_t<winrt::Windows::UI::Xaml::Documents::IHyperlink>::remove_Click>;
        [[nodiscard]] Click_revoker Click(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Documents::Hyperlink, winrt::Windows::UI::Xaml::Documents::HyperlinkClickEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) Click(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IHyperlink>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IHyperlink<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IHyperlink2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Documents::UnderlineStyle) UnderlineStyle() const;
        WINRT_IMPL_AUTO(void) UnderlineStyle(winrt::Windows::UI::Xaml::Documents::UnderlineStyle const& value) const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IHyperlink2>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IHyperlink2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IHyperlink3
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) XYFocusLeft() const;
        WINRT_IMPL_AUTO(void) XYFocusLeft(winrt::Windows::UI::Xaml::DependencyObject const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) XYFocusRight() const;
        WINRT_IMPL_AUTO(void) XYFocusRight(winrt::Windows::UI::Xaml::DependencyObject const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) XYFocusUp() const;
        WINRT_IMPL_AUTO(void) XYFocusUp(winrt::Windows::UI::Xaml::DependencyObject const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) XYFocusDown() const;
        WINRT_IMPL_AUTO(void) XYFocusDown(winrt::Windows::UI::Xaml::DependencyObject const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::ElementSoundMode) ElementSoundMode() const;
        WINRT_IMPL_AUTO(void) ElementSoundMode(winrt::Windows::UI::Xaml::ElementSoundMode const& value) const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IHyperlink3>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IHyperlink3<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IHyperlink4
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FocusState) FocusState() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy) XYFocusUpNavigationStrategy() const;
        WINRT_IMPL_AUTO(void) XYFocusUpNavigationStrategy(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy) XYFocusDownNavigationStrategy() const;
        WINRT_IMPL_AUTO(void) XYFocusDownNavigationStrategy(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy) XYFocusLeftNavigationStrategy() const;
        WINRT_IMPL_AUTO(void) XYFocusLeftNavigationStrategy(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy) XYFocusRightNavigationStrategy() const;
        WINRT_IMPL_AUTO(void) XYFocusRightNavigationStrategy(winrt::Windows::UI::Xaml::Input::XYFocusNavigationStrategy const& value) const;
        WINRT_IMPL_AUTO(winrt::event_token) GotFocus(winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const;
        using GotFocus_revoker = impl::event_revoker<winrt::Windows::UI::Xaml::Documents::IHyperlink4, &impl::abi_t<winrt::Windows::UI::Xaml::Documents::IHyperlink4>::remove_GotFocus>;
        [[nodiscard]] GotFocus_revoker GotFocus(auto_revoke_t, winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const;
        WINRT_IMPL_AUTO(void) GotFocus(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) LostFocus(winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const;
        using LostFocus_revoker = impl::event_revoker<winrt::Windows::UI::Xaml::Documents::IHyperlink4, &impl::abi_t<winrt::Windows::UI::Xaml::Documents::IHyperlink4>::remove_LostFocus>;
        [[nodiscard]] LostFocus_revoker LostFocus(auto_revoke_t, winrt::Windows::UI::Xaml::RoutedEventHandler const& handler) const;
        WINRT_IMPL_AUTO(void) LostFocus(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(bool) Focus(winrt::Windows::UI::Xaml::FocusState const& value) const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IHyperlink4>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IHyperlink4<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IHyperlink5
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsTabStop() const;
        WINRT_IMPL_AUTO(void) IsTabStop(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) TabIndex() const;
        WINRT_IMPL_AUTO(void) TabIndex(int32_t value) const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IHyperlink5>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IHyperlink5<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IHyperlinkClickEventArgs
    {
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IHyperlinkClickEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IHyperlinkClickEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IHyperlinkStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) NavigateUriProperty() const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IHyperlinkStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IHyperlinkStatics2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) UnderlineStyleProperty() const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics2>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IHyperlinkStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IHyperlinkStatics3
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) XYFocusLeftProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) XYFocusRightProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) XYFocusUpProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) XYFocusDownProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) ElementSoundModeProperty() const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics3>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IHyperlinkStatics3<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IHyperlinkStatics4
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) FocusStateProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) XYFocusUpNavigationStrategyProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) XYFocusDownNavigationStrategyProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) XYFocusLeftNavigationStrategyProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) XYFocusRightNavigationStrategyProperty() const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics4>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IHyperlinkStatics4<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IHyperlinkStatics5
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) IsTabStopProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) TabIndexProperty() const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IHyperlinkStatics5>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IHyperlinkStatics5<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IInline
    {
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IInline>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IInline<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IInlineFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Documents::Inline) CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IInlineFactory>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IInlineFactory<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IInlineUIContainer
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::UIElement) Child() const;
        WINRT_IMPL_AUTO(void) Child(winrt::Windows::UI::Xaml::UIElement const& value) const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IInlineUIContainer>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IInlineUIContainer<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IItalic
    {
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IItalic>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IItalic<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_ILineBreak
    {
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::ILineBreak>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_ILineBreak<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IParagraph
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Documents::InlineCollection) Inlines() const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) TextIndent() const;
        WINRT_IMPL_AUTO(void) TextIndent(double value) const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IParagraph>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IParagraph<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IParagraphStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) TextIndentProperty() const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IParagraphStatics>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IParagraphStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IPlaceContentLinkProvider
    {
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IPlaceContentLinkProvider>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IPlaceContentLinkProvider<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IRun
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Text() const;
        WINRT_IMPL_AUTO(void) Text(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FlowDirection) FlowDirection() const;
        WINRT_IMPL_AUTO(void) FlowDirection(winrt::Windows::UI::Xaml::FlowDirection const& value) const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IRun>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IRun<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IRunStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) FlowDirectionProperty() const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IRunStatics>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IRunStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_ISpan
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Documents::InlineCollection) Inlines() const;
        WINRT_IMPL_AUTO(void) Inlines(winrt::Windows::UI::Xaml::Documents::InlineCollection const& value) const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::ISpan>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_ISpan<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_ISpanFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Documents::Span) CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::ISpanFactory>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_ISpanFactory<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_ITextElement
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Name() const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) FontSize() const;
        WINRT_IMPL_AUTO(void) FontSize(double value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::FontFamily) FontFamily() const;
        WINRT_IMPL_AUTO(void) FontFamily(winrt::Windows::UI::Xaml::Media::FontFamily const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Text::FontWeight) FontWeight() const;
        WINRT_IMPL_AUTO(void) FontWeight(winrt::Windows::UI::Text::FontWeight const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Text::FontStyle) FontStyle() const;
        WINRT_IMPL_AUTO(void) FontStyle(winrt::Windows::UI::Text::FontStyle const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Text::FontStretch) FontStretch() const;
        WINRT_IMPL_AUTO(void) FontStretch(winrt::Windows::UI::Text::FontStretch const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) CharacterSpacing() const;
        WINRT_IMPL_AUTO(void) CharacterSpacing(int32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) Foreground() const;
        WINRT_IMPL_AUTO(void) Foreground(winrt::Windows::UI::Xaml::Media::Brush const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Language() const;
        WINRT_IMPL_AUTO(void) Language(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Documents::TextPointer) ContentStart() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Documents::TextPointer) ContentEnd() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Documents::TextPointer) ElementStart() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Documents::TextPointer) ElementEnd() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IInspectable) FindName(param::hstring const& name) const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::ITextElement>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextElement<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_ITextElement2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsTextScaleFactorEnabled() const;
        WINRT_IMPL_AUTO(void) IsTextScaleFactorEnabled(bool value) const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::ITextElement2>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextElement2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_ITextElement3
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AllowFocusOnInteraction() const;
        WINRT_IMPL_AUTO(void) AllowFocusOnInteraction(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) AccessKey() const;
        WINRT_IMPL_AUTO(void) AccessKey(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ExitDisplayModeOnAccessKeyInvoked() const;
        WINRT_IMPL_AUTO(void) ExitDisplayModeOnAccessKeyInvoked(bool value) const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::ITextElement3>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextElement3<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_ITextElement4
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Text::TextDecorations) TextDecorations() const;
        WINRT_IMPL_AUTO(void) TextDecorations(winrt::Windows::UI::Text::TextDecorations const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsAccessKeyScope() const;
        WINRT_IMPL_AUTO(void) IsAccessKeyScope(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) AccessKeyScopeOwner() const;
        WINRT_IMPL_AUTO(void) AccessKeyScopeOwner(winrt::Windows::UI::Xaml::DependencyObject const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Input::KeyTipPlacementMode) KeyTipPlacementMode() const;
        WINRT_IMPL_AUTO(void) KeyTipPlacementMode(winrt::Windows::UI::Xaml::Input::KeyTipPlacementMode const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) KeyTipHorizontalOffset() const;
        WINRT_IMPL_AUTO(void) KeyTipHorizontalOffset(double value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) KeyTipVerticalOffset() const;
        WINRT_IMPL_AUTO(void) KeyTipVerticalOffset(double value) const;
        WINRT_IMPL_AUTO(winrt::event_token) AccessKeyDisplayRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Documents::TextElement, winrt::Windows::UI::Xaml::Input::AccessKeyDisplayRequestedEventArgs> const& handler) const;
        using AccessKeyDisplayRequested_revoker = impl::event_revoker<winrt::Windows::UI::Xaml::Documents::ITextElement4, &impl::abi_t<winrt::Windows::UI::Xaml::Documents::ITextElement4>::remove_AccessKeyDisplayRequested>;
        [[nodiscard]] AccessKeyDisplayRequested_revoker AccessKeyDisplayRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Documents::TextElement, winrt::Windows::UI::Xaml::Input::AccessKeyDisplayRequestedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) AccessKeyDisplayRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) AccessKeyDisplayDismissed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Documents::TextElement, winrt::Windows::UI::Xaml::Input::AccessKeyDisplayDismissedEventArgs> const& handler) const;
        using AccessKeyDisplayDismissed_revoker = impl::event_revoker<winrt::Windows::UI::Xaml::Documents::ITextElement4, &impl::abi_t<winrt::Windows::UI::Xaml::Documents::ITextElement4>::remove_AccessKeyDisplayDismissed>;
        [[nodiscard]] AccessKeyDisplayDismissed_revoker AccessKeyDisplayDismissed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Documents::TextElement, winrt::Windows::UI::Xaml::Input::AccessKeyDisplayDismissedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) AccessKeyDisplayDismissed(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) AccessKeyInvoked(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Documents::TextElement, winrt::Windows::UI::Xaml::Input::AccessKeyInvokedEventArgs> const& handler) const;
        using AccessKeyInvoked_revoker = impl::event_revoker<winrt::Windows::UI::Xaml::Documents::ITextElement4, &impl::abi_t<winrt::Windows::UI::Xaml::Documents::ITextElement4>::remove_AccessKeyInvoked>;
        [[nodiscard]] AccessKeyInvoked_revoker AccessKeyInvoked(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::Xaml::Documents::TextElement, winrt::Windows::UI::Xaml::Input::AccessKeyInvokedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) AccessKeyInvoked(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::ITextElement4>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextElement4<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_ITextElement5
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::XamlRoot) XamlRoot() const;
        WINRT_IMPL_AUTO(void) XamlRoot(winrt::Windows::UI::Xaml::XamlRoot const& value) const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::ITextElement5>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextElement5<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_ITextElementFactory
    {
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::ITextElementFactory>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextElementFactory<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_ITextElementOverrides
    {
        WINRT_IMPL_AUTO(void) OnDisconnectVisualChildren() const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::ITextElementOverrides>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextElementOverrides<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_ITextElementStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) FontSizeProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) FontFamilyProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) FontWeightProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) FontStyleProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) FontStretchProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) CharacterSpacingProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) ForegroundProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) LanguageProperty() const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::ITextElementStatics>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextElementStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_ITextElementStatics2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) IsTextScaleFactorEnabledProperty() const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::ITextElementStatics2>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextElementStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_ITextElementStatics3
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) AllowFocusOnInteractionProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) AccessKeyProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) ExitDisplayModeOnAccessKeyInvokedProperty() const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::ITextElementStatics3>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextElementStatics3<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_ITextElementStatics4
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) TextDecorationsProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) IsAccessKeyScopeProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) AccessKeyScopeOwnerProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) KeyTipPlacementModeProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) KeyTipHorizontalOffsetProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) KeyTipVerticalOffsetProperty() const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::ITextElementStatics4>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextElementStatics4<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_ITextHighlighter
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVector<winrt::Windows::UI::Xaml::Documents::TextRange>) Ranges() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) Foreground() const;
        WINRT_IMPL_AUTO(void) Foreground(winrt::Windows::UI::Xaml::Media::Brush const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Media::Brush) Background() const;
        WINRT_IMPL_AUTO(void) Background(winrt::Windows::UI::Xaml::Media::Brush const& value) const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::ITextHighlighter>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextHighlighter<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_ITextHighlighterBase
    {
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::ITextHighlighterBase>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextHighlighterBase<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_ITextHighlighterBaseFactory
    {
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::ITextHighlighterBaseFactory>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextHighlighterBaseFactory<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_ITextHighlighterFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Documents::TextHighlighter) CreateInstance(winrt::Windows::Foundation::IInspectable const& baseInterface, winrt::Windows::Foundation::IInspectable& innerInterface) const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::ITextHighlighterFactory>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextHighlighterFactory<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_ITextHighlighterStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) ForegroundProperty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) BackgroundProperty() const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::ITextHighlighterStatics>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextHighlighterStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_ITextPointer
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyObject) Parent() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FrameworkElement) VisualParent() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Documents::LogicalDirection) LogicalDirection() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) Offset() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) GetCharacterRect(winrt::Windows::UI::Xaml::Documents::LogicalDirection const& direction) const;
        WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::Documents::TextPointer) GetPositionAtOffset(int32_t offset, winrt::Windows::UI::Xaml::Documents::LogicalDirection const& direction) const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::ITextPointer>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITextPointer<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_ITypography
    {
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::ITypography>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITypography<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_ITypographyStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) AnnotationAlternatesProperty() const;
        WINRT_IMPL_AUTO(int32_t) GetAnnotationAlternates(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetAnnotationAlternates(winrt::Windows::UI::Xaml::DependencyObject const& element, int32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) EastAsianExpertFormsProperty() const;
        WINRT_IMPL_AUTO(bool) GetEastAsianExpertForms(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetEastAsianExpertForms(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) EastAsianLanguageProperty() const;
        WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FontEastAsianLanguage) GetEastAsianLanguage(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetEastAsianLanguage(winrt::Windows::UI::Xaml::DependencyObject const& element, winrt::Windows::UI::Xaml::FontEastAsianLanguage const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) EastAsianWidthsProperty() const;
        WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FontEastAsianWidths) GetEastAsianWidths(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetEastAsianWidths(winrt::Windows::UI::Xaml::DependencyObject const& element, winrt::Windows::UI::Xaml::FontEastAsianWidths const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) StandardLigaturesProperty() const;
        WINRT_IMPL_AUTO(bool) GetStandardLigatures(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetStandardLigatures(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) ContextualLigaturesProperty() const;
        WINRT_IMPL_AUTO(bool) GetContextualLigatures(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetContextualLigatures(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) DiscretionaryLigaturesProperty() const;
        WINRT_IMPL_AUTO(bool) GetDiscretionaryLigatures(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetDiscretionaryLigatures(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) HistoricalLigaturesProperty() const;
        WINRT_IMPL_AUTO(bool) GetHistoricalLigatures(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetHistoricalLigatures(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) StandardSwashesProperty() const;
        WINRT_IMPL_AUTO(int32_t) GetStandardSwashes(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetStandardSwashes(winrt::Windows::UI::Xaml::DependencyObject const& element, int32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) ContextualSwashesProperty() const;
        WINRT_IMPL_AUTO(int32_t) GetContextualSwashes(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetContextualSwashes(winrt::Windows::UI::Xaml::DependencyObject const& element, int32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) ContextualAlternatesProperty() const;
        WINRT_IMPL_AUTO(bool) GetContextualAlternates(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetContextualAlternates(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) StylisticAlternatesProperty() const;
        WINRT_IMPL_AUTO(int32_t) GetStylisticAlternates(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetStylisticAlternates(winrt::Windows::UI::Xaml::DependencyObject const& element, int32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) StylisticSet1Property() const;
        WINRT_IMPL_AUTO(bool) GetStylisticSet1(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetStylisticSet1(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) StylisticSet2Property() const;
        WINRT_IMPL_AUTO(bool) GetStylisticSet2(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetStylisticSet2(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) StylisticSet3Property() const;
        WINRT_IMPL_AUTO(bool) GetStylisticSet3(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetStylisticSet3(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) StylisticSet4Property() const;
        WINRT_IMPL_AUTO(bool) GetStylisticSet4(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetStylisticSet4(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) StylisticSet5Property() const;
        WINRT_IMPL_AUTO(bool) GetStylisticSet5(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetStylisticSet5(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) StylisticSet6Property() const;
        WINRT_IMPL_AUTO(bool) GetStylisticSet6(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetStylisticSet6(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) StylisticSet7Property() const;
        WINRT_IMPL_AUTO(bool) GetStylisticSet7(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetStylisticSet7(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) StylisticSet8Property() const;
        WINRT_IMPL_AUTO(bool) GetStylisticSet8(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetStylisticSet8(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) StylisticSet9Property() const;
        WINRT_IMPL_AUTO(bool) GetStylisticSet9(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetStylisticSet9(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) StylisticSet10Property() const;
        WINRT_IMPL_AUTO(bool) GetStylisticSet10(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetStylisticSet10(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) StylisticSet11Property() const;
        WINRT_IMPL_AUTO(bool) GetStylisticSet11(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetStylisticSet11(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) StylisticSet12Property() const;
        WINRT_IMPL_AUTO(bool) GetStylisticSet12(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetStylisticSet12(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) StylisticSet13Property() const;
        WINRT_IMPL_AUTO(bool) GetStylisticSet13(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetStylisticSet13(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) StylisticSet14Property() const;
        WINRT_IMPL_AUTO(bool) GetStylisticSet14(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetStylisticSet14(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) StylisticSet15Property() const;
        WINRT_IMPL_AUTO(bool) GetStylisticSet15(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetStylisticSet15(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) StylisticSet16Property() const;
        WINRT_IMPL_AUTO(bool) GetStylisticSet16(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetStylisticSet16(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) StylisticSet17Property() const;
        WINRT_IMPL_AUTO(bool) GetStylisticSet17(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetStylisticSet17(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) StylisticSet18Property() const;
        WINRT_IMPL_AUTO(bool) GetStylisticSet18(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetStylisticSet18(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) StylisticSet19Property() const;
        WINRT_IMPL_AUTO(bool) GetStylisticSet19(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetStylisticSet19(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) StylisticSet20Property() const;
        WINRT_IMPL_AUTO(bool) GetStylisticSet20(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetStylisticSet20(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) CapitalsProperty() const;
        WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FontCapitals) GetCapitals(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetCapitals(winrt::Windows::UI::Xaml::DependencyObject const& element, winrt::Windows::UI::Xaml::FontCapitals const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) CapitalSpacingProperty() const;
        WINRT_IMPL_AUTO(bool) GetCapitalSpacing(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetCapitalSpacing(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) KerningProperty() const;
        WINRT_IMPL_AUTO(bool) GetKerning(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetKerning(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) CaseSensitiveFormsProperty() const;
        WINRT_IMPL_AUTO(bool) GetCaseSensitiveForms(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetCaseSensitiveForms(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) HistoricalFormsProperty() const;
        WINRT_IMPL_AUTO(bool) GetHistoricalForms(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetHistoricalForms(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) FractionProperty() const;
        WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FontFraction) GetFraction(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetFraction(winrt::Windows::UI::Xaml::DependencyObject const& element, winrt::Windows::UI::Xaml::FontFraction const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) NumeralStyleProperty() const;
        WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FontNumeralStyle) GetNumeralStyle(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetNumeralStyle(winrt::Windows::UI::Xaml::DependencyObject const& element, winrt::Windows::UI::Xaml::FontNumeralStyle const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) NumeralAlignmentProperty() const;
        WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FontNumeralAlignment) GetNumeralAlignment(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetNumeralAlignment(winrt::Windows::UI::Xaml::DependencyObject const& element, winrt::Windows::UI::Xaml::FontNumeralAlignment const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) SlashedZeroProperty() const;
        WINRT_IMPL_AUTO(bool) GetSlashedZero(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetSlashedZero(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) MathematicalGreekProperty() const;
        WINRT_IMPL_AUTO(bool) GetMathematicalGreek(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetMathematicalGreek(winrt::Windows::UI::Xaml::DependencyObject const& element, bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::DependencyProperty) VariantsProperty() const;
        WINRT_IMPL_AUTO(winrt::Windows::UI::Xaml::FontVariants) GetVariants(winrt::Windows::UI::Xaml::DependencyObject const& element) const;
        WINRT_IMPL_AUTO(void) SetVariants(winrt::Windows::UI::Xaml::DependencyObject const& element, winrt::Windows::UI::Xaml::FontVariants const& value) const;
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::ITypographyStatics>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_ITypographyStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_Xaml_Documents_IUnderline
    {
    };
    template <> struct consume<winrt::Windows::UI::Xaml::Documents::IUnderline>
    {
        template <typename D> using type = consume_Windows_UI_Xaml_Documents_IUnderline<D>;
    };
    struct struct_Windows_UI_Xaml_Documents_TextRange
    {
        int32_t StartIndex;
        int32_t Length;
    };
    template <> struct abi<Windows::UI::Xaml::Documents::TextRange>
    {
        using type = struct_Windows_UI_Xaml_Documents_TextRange;
    };
}
#endif
