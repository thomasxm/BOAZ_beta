// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Web_Http_Diagnostics_0_H
#define WINRT_Windows_Web_Http_Diagnostics_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct EventRegistrationToken;
    template <typename T> struct __declspec(empty_bases) IReference;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
    struct Uri;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IVectorView;
}
WINRT_EXPORT namespace winrt::Windows::System::Diagnostics
{
    struct ProcessDiagnosticInfo;
}
WINRT_EXPORT namespace winrt::Windows::Web::Http
{
    struct HttpRequestMessage;
    struct HttpResponseMessage;
}
WINRT_EXPORT namespace winrt::Windows::Web::Http::Diagnostics
{
    enum class HttpDiagnosticRequestInitiator : int32_t
    {
        ParsedElement = 0,
        Script = 1,
        Image = 2,
        Link = 3,
        Style = 4,
        XmlHttpRequest = 5,
        Media = 6,
        HtmlDownload = 7,
        Prefetch = 8,
        Other = 9,
        CrossOriginPreFlight = 10,
        Fetch = 11,
        Beacon = 12,
    };
    struct IHttpDiagnosticProvider;
    struct IHttpDiagnosticProviderRequestResponseCompletedEventArgs;
    struct IHttpDiagnosticProviderRequestResponseTimestamps;
    struct IHttpDiagnosticProviderRequestSentEventArgs;
    struct IHttpDiagnosticProviderResponseReceivedEventArgs;
    struct IHttpDiagnosticProviderStatics;
    struct IHttpDiagnosticSourceLocation;
    struct HttpDiagnosticProvider;
    struct HttpDiagnosticProviderRequestResponseCompletedEventArgs;
    struct HttpDiagnosticProviderRequestResponseTimestamps;
    struct HttpDiagnosticProviderRequestSentEventArgs;
    struct HttpDiagnosticProviderResponseReceivedEventArgs;
    struct HttpDiagnosticSourceLocation;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseCompletedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestSentEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderResponseReceivedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticSourceLocation>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProvider>{ using type = class_category; };
    template <> struct category<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestResponseCompletedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestResponseTimestamps>{ using type = class_category; };
    template <> struct category<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestSentEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderResponseReceivedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticSourceLocation>{ using type = class_category; };
    template <> struct category<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticRequestInitiator>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProvider> = L"Windows.Web.Http.Diagnostics.HttpDiagnosticProvider";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestResponseCompletedEventArgs> = L"Windows.Web.Http.Diagnostics.HttpDiagnosticProviderRequestResponseCompletedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestResponseTimestamps> = L"Windows.Web.Http.Diagnostics.HttpDiagnosticProviderRequestResponseTimestamps";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestSentEventArgs> = L"Windows.Web.Http.Diagnostics.HttpDiagnosticProviderRequestSentEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderResponseReceivedEventArgs> = L"Windows.Web.Http.Diagnostics.HttpDiagnosticProviderResponseReceivedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticSourceLocation> = L"Windows.Web.Http.Diagnostics.HttpDiagnosticSourceLocation";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticRequestInitiator> = L"Windows.Web.Http.Diagnostics.HttpDiagnosticRequestInitiator";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider> = L"Windows.Web.Http.Diagnostics.IHttpDiagnosticProvider";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseCompletedEventArgs> = L"Windows.Web.Http.Diagnostics.IHttpDiagnosticProviderRequestResponseCompletedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps> = L"Windows.Web.Http.Diagnostics.IHttpDiagnosticProviderRequestResponseTimestamps";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestSentEventArgs> = L"Windows.Web.Http.Diagnostics.IHttpDiagnosticProviderRequestSentEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderResponseReceivedEventArgs> = L"Windows.Web.Http.Diagnostics.IHttpDiagnosticProviderResponseReceivedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderStatics> = L"Windows.Web.Http.Diagnostics.IHttpDiagnosticProviderStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticSourceLocation> = L"Windows.Web.Http.Diagnostics.IHttpDiagnosticSourceLocation";
    template <> inline constexpr guid guid_v<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider>{ 0xBD811501,0xA056,0x4D39,{ 0xB1,0x74,0x83,0x3B,0x7B,0x03,0xB0,0x2C } }; // BD811501-A056-4D39-B174-833B7B03B02C
    template <> inline constexpr guid guid_v<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseCompletedEventArgs>{ 0x735F98EE,0x94F6,0x4532,{ 0xB2,0x6E,0x61,0xE1,0xB1,0xE4,0xEF,0xD4 } }; // 735F98EE-94F6-4532-B26E-61E1B1E4EFD4
    template <> inline constexpr guid guid_v<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps>{ 0xE0AFDE10,0x55CF,0x4C01,{ 0x91,0xD4,0xA2,0x05,0x57,0xD8,0x49,0xF0 } }; // E0AFDE10-55CF-4C01-91D4-A20557D849F0
    template <> inline constexpr guid guid_v<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestSentEventArgs>{ 0x3F5196D0,0x4C1F,0x4EBE,{ 0xA5,0x7A,0x06,0x93,0x07,0x71,0xC5,0x0D } }; // 3F5196D0-4C1F-4EBE-A57A-06930771C50D
    template <> inline constexpr guid guid_v<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderResponseReceivedEventArgs>{ 0xA0A2566C,0xAB5F,0x4D66,{ 0xBB,0x2D,0x08,0x4C,0xF4,0x16,0x35,0xD0 } }; // A0A2566C-AB5F-4D66-BB2D-084CF41635D0
    template <> inline constexpr guid guid_v<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderStatics>{ 0x5B824EC1,0x6A6C,0x47CC,{ 0xAF,0xEC,0x1E,0x86,0xBC,0x26,0x05,0x3B } }; // 5B824EC1-6A6C-47CC-AFEC-1E86BC26053B
    template <> inline constexpr guid guid_v<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticSourceLocation>{ 0x54A9D260,0x8860,0x423F,{ 0xB6,0xFA,0xD7,0x77,0x16,0xF6,0x47,0xA7 } }; // 54A9D260-8860-423F-B6FA-D77716F647A7
    template <> struct default_interface<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProvider>{ using type = winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider; };
    template <> struct default_interface<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestResponseCompletedEventArgs>{ using type = winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseCompletedEventArgs; };
    template <> struct default_interface<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestResponseTimestamps>{ using type = winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps; };
    template <> struct default_interface<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestSentEventArgs>{ using type = winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestSentEventArgs; };
    template <> struct default_interface<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderResponseReceivedEventArgs>{ using type = winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderResponseReceivedEventArgs; };
    template <> struct default_interface<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticSourceLocation>{ using type = winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticSourceLocation; };
    template <> struct abi<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Start() noexcept = 0;
            virtual int32_t __stdcall Stop() noexcept = 0;
            virtual int32_t __stdcall add_RequestSent(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_RequestSent(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ResponseReceived(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ResponseReceived(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_RequestResponseCompleted(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_RequestResponseCompleted(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseCompletedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ActivityId(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall get_Timestamps(void**) noexcept = 0;
            virtual int32_t __stdcall get_RequestedUri(void**) noexcept = 0;
            virtual int32_t __stdcall get_ProcessId(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ThreadId(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Initiator(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_SourceLocations(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_CacheCheckedTimestamp(void**) noexcept = 0;
            virtual int32_t __stdcall get_ConnectionInitiatedTimestamp(void**) noexcept = 0;
            virtual int32_t __stdcall get_NameResolvedTimestamp(void**) noexcept = 0;
            virtual int32_t __stdcall get_SslNegotiatedTimestamp(void**) noexcept = 0;
            virtual int32_t __stdcall get_ConnectionCompletedTimestamp(void**) noexcept = 0;
            virtual int32_t __stdcall get_RequestSentTimestamp(void**) noexcept = 0;
            virtual int32_t __stdcall get_RequestCompletedTimestamp(void**) noexcept = 0;
            virtual int32_t __stdcall get_ResponseReceivedTimestamp(void**) noexcept = 0;
            virtual int32_t __stdcall get_ResponseCompletedTimestamp(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestSentEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Timestamp(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_ActivityId(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall get_Message(void**) noexcept = 0;
            virtual int32_t __stdcall get_ProcessId(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ThreadId(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Initiator(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_SourceLocations(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderResponseReceivedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Timestamp(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_ActivityId(winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall get_Message(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateFromProcessDiagnosticInfo(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticSourceLocation>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_SourceUri(void**) noexcept = 0;
            virtual int32_t __stdcall get_LineNumber(uint64_t*) noexcept = 0;
            virtual int32_t __stdcall get_ColumnNumber(uint64_t*) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider
    {
        WINRT_IMPL_AUTO(void) Start() const;
        WINRT_IMPL_AUTO(void) Stop() const;
        WINRT_IMPL_AUTO(winrt::event_token) RequestSent(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProvider, winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestSentEventArgs> const& handler) const;
        using RequestSent_revoker = impl::event_revoker<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider, &impl::abi_t<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider>::remove_RequestSent>;
        [[nodiscard]] RequestSent_revoker RequestSent(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProvider, winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestSentEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) RequestSent(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ResponseReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProvider, winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderResponseReceivedEventArgs> const& handler) const;
        using ResponseReceived_revoker = impl::event_revoker<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider, &impl::abi_t<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider>::remove_ResponseReceived>;
        [[nodiscard]] ResponseReceived_revoker ResponseReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProvider, winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderResponseReceivedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ResponseReceived(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) RequestResponseCompleted(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProvider, winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestResponseCompletedEventArgs> const& handler) const;
        using RequestResponseCompleted_revoker = impl::event_revoker<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider, &impl::abi_t<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider>::remove_RequestResponseCompleted>;
        [[nodiscard]] RequestResponseCompleted_revoker RequestResponseCompleted(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProvider, winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestResponseCompletedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) RequestResponseCompleted(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProvider>
    {
        template <typename D> using type = consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProvider<D>;
    };
    template <typename D>
    struct consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseCompletedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) ActivityId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProviderRequestResponseTimestamps) Timestamps() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) RequestedUri() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ProcessId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ThreadId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticRequestInitiator) Initiator() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticSourceLocation>) SourceLocations() const;
    };
    template <> struct consume<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseCompletedEventArgs>
    {
        template <typename D> using type = consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseCompletedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseTimestamps
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) CacheCheckedTimestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) ConnectionInitiatedTimestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) NameResolvedTimestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) SslNegotiatedTimestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) ConnectionCompletedTimestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) RequestSentTimestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) RequestCompletedTimestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) ResponseReceivedTimestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::DateTime>) ResponseCompletedTimestamp() const;
    };
    template <> struct consume<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestResponseTimestamps>
    {
        template <typename D> using type = consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestResponseTimestamps<D>;
    };
    template <typename D>
    struct consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestSentEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) Timestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) ActivityId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Web::Http::HttpRequestMessage) Message() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ProcessId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ThreadId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticRequestInitiator) Initiator() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticSourceLocation>) SourceLocations() const;
    };
    template <> struct consume<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderRequestSentEventArgs>
    {
        template <typename D> using type = consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderRequestSentEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderResponseReceivedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) Timestamp() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::guid) ActivityId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Web::Http::HttpResponseMessage) Message() const;
    };
    template <> struct consume<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderResponseReceivedEventArgs>
    {
        template <typename D> using type = consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderResponseReceivedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Web::Http::Diagnostics::HttpDiagnosticProvider) CreateFromProcessDiagnosticInfo(winrt::Windows::System::Diagnostics::ProcessDiagnosticInfo const& processDiagnosticInfo) const;
    };
    template <> struct consume<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticProviderStatics>
    {
        template <typename D> using type = consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticProviderStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticSourceLocation
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Uri) SourceUri() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint64_t) LineNumber() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint64_t) ColumnNumber() const;
    };
    template <> struct consume<winrt::Windows::Web::Http::Diagnostics::IHttpDiagnosticSourceLocation>
    {
        template <typename D> using type = consume_Windows_Web_Http_Diagnostics_IHttpDiagnosticSourceLocation<D>;
    };
}
#endif
