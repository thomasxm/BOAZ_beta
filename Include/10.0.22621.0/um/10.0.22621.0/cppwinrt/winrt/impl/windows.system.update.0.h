// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_System_Update_0_H
#define WINRT_Windows_System_Update_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    template <typename T> struct __declspec(empty_bases) EventHandler;
    struct EventRegistrationToken;
    struct HResult;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IVectorView;
}
WINRT_EXPORT namespace winrt::Windows::System::Update
{
    enum class SystemUpdateAttentionRequiredReason : int32_t
    {
        None = 0,
        NetworkRequired = 1,
        InsufficientDiskSpace = 2,
        InsufficientBattery = 3,
        UpdateBlocked = 4,
    };
    enum class SystemUpdateItemState : int32_t
    {
        NotStarted = 0,
        Initializing = 1,
        Preparing = 2,
        Calculating = 3,
        Downloading = 4,
        Installing = 5,
        Completed = 6,
        RebootRequired = 7,
        Error = 8,
    };
    enum class SystemUpdateManagerState : int32_t
    {
        Idle = 0,
        Detecting = 1,
        ReadyToDownload = 2,
        Downloading = 3,
        ReadyToInstall = 4,
        Installing = 5,
        RebootRequired = 6,
        ReadyToFinalize = 7,
        Finalizing = 8,
        Completed = 9,
        AttentionRequired = 10,
        Error = 11,
    };
    enum class SystemUpdateStartInstallAction : int32_t
    {
        UpToReboot = 0,
        AllowReboot = 1,
    };
    struct ISystemUpdateItem;
    struct ISystemUpdateLastErrorInfo;
    struct ISystemUpdateManagerStatics;
    struct SystemUpdateItem;
    struct SystemUpdateLastErrorInfo;
    struct SystemUpdateManager;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::System::Update::ISystemUpdateItem>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::Update::ISystemUpdateLastErrorInfo>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::Update::ISystemUpdateManagerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::System::Update::SystemUpdateItem>{ using type = class_category; };
    template <> struct category<winrt::Windows::System::Update::SystemUpdateLastErrorInfo>{ using type = class_category; };
    template <> struct category<winrt::Windows::System::Update::SystemUpdateManager>{ using type = class_category; };
    template <> struct category<winrt::Windows::System::Update::SystemUpdateAttentionRequiredReason>{ using type = enum_category; };
    template <> struct category<winrt::Windows::System::Update::SystemUpdateItemState>{ using type = enum_category; };
    template <> struct category<winrt::Windows::System::Update::SystemUpdateManagerState>{ using type = enum_category; };
    template <> struct category<winrt::Windows::System::Update::SystemUpdateStartInstallAction>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::System::Update::SystemUpdateItem> = L"Windows.System.Update.SystemUpdateItem";
    template <> inline constexpr auto& name_v<winrt::Windows::System::Update::SystemUpdateLastErrorInfo> = L"Windows.System.Update.SystemUpdateLastErrorInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::System::Update::SystemUpdateManager> = L"Windows.System.Update.SystemUpdateManager";
    template <> inline constexpr auto& name_v<winrt::Windows::System::Update::SystemUpdateAttentionRequiredReason> = L"Windows.System.Update.SystemUpdateAttentionRequiredReason";
    template <> inline constexpr auto& name_v<winrt::Windows::System::Update::SystemUpdateItemState> = L"Windows.System.Update.SystemUpdateItemState";
    template <> inline constexpr auto& name_v<winrt::Windows::System::Update::SystemUpdateManagerState> = L"Windows.System.Update.SystemUpdateManagerState";
    template <> inline constexpr auto& name_v<winrt::Windows::System::Update::SystemUpdateStartInstallAction> = L"Windows.System.Update.SystemUpdateStartInstallAction";
    template <> inline constexpr auto& name_v<winrt::Windows::System::Update::ISystemUpdateItem> = L"Windows.System.Update.ISystemUpdateItem";
    template <> inline constexpr auto& name_v<winrt::Windows::System::Update::ISystemUpdateLastErrorInfo> = L"Windows.System.Update.ISystemUpdateLastErrorInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::System::Update::ISystemUpdateManagerStatics> = L"Windows.System.Update.ISystemUpdateManagerStatics";
    template <> inline constexpr guid guid_v<winrt::Windows::System::Update::ISystemUpdateItem>{ 0x779740EB,0x5624,0x519E,{ 0xA8,0xE2,0x09,0xE9,0x17,0x3B,0x3F,0xB7 } }; // 779740EB-5624-519E-A8E2-09E9173B3FB7
    template <> inline constexpr guid guid_v<winrt::Windows::System::Update::ISystemUpdateLastErrorInfo>{ 0x7EE887F7,0x8A44,0x5B6E,{ 0xBD,0x07,0x7A,0xEC,0xE4,0x11,0x6E,0xA9 } }; // 7EE887F7-8A44-5B6E-BD07-7AECE4116EA9
    template <> inline constexpr guid guid_v<winrt::Windows::System::Update::ISystemUpdateManagerStatics>{ 0xB2D3FCEF,0x2971,0x51BE,{ 0xB4,0x1A,0x8B,0xD7,0x03,0xBB,0x70,0x1A } }; // B2D3FCEF-2971-51BE-B41A-8BD703BB701A
    template <> struct default_interface<winrt::Windows::System::Update::SystemUpdateItem>{ using type = winrt::Windows::System::Update::ISystemUpdateItem; };
    template <> struct default_interface<winrt::Windows::System::Update::SystemUpdateLastErrorInfo>{ using type = winrt::Windows::System::Update::ISystemUpdateLastErrorInfo; };
    template <> struct abi<winrt::Windows::System::Update::ISystemUpdateItem>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_State(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Title(void**) noexcept = 0;
            virtual int32_t __stdcall get_Description(void**) noexcept = 0;
            virtual int32_t __stdcall get_Id(void**) noexcept = 0;
            virtual int32_t __stdcall get_Revision(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_DownloadProgress(double*) noexcept = 0;
            virtual int32_t __stdcall get_InstallProgress(double*) noexcept = 0;
            virtual int32_t __stdcall get_ExtendedError(winrt::hresult*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::System::Update::ISystemUpdateLastErrorInfo>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_State(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ExtendedError(winrt::hresult*) noexcept = 0;
            virtual int32_t __stdcall get_IsInteractive(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::System::Update::ISystemUpdateManagerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall IsSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_State(int32_t*) noexcept = 0;
            virtual int32_t __stdcall add_StateChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_StateChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall get_DownloadProgress(double*) noexcept = 0;
            virtual int32_t __stdcall get_InstallProgress(double*) noexcept = 0;
            virtual int32_t __stdcall get_UserActiveHoursStart(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_UserActiveHoursEnd(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_UserActiveHoursMax(int32_t*) noexcept = 0;
            virtual int32_t __stdcall TrySetUserActiveHours(int64_t, int64_t, bool*) noexcept = 0;
            virtual int32_t __stdcall get_LastUpdateCheckTime(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_LastUpdateInstallTime(int64_t*) noexcept = 0;
            virtual int32_t __stdcall get_LastErrorInfo(void**) noexcept = 0;
            virtual int32_t __stdcall GetAutomaticRebootBlockIds(void**) noexcept = 0;
            virtual int32_t __stdcall BlockAutomaticRebootAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall UnblockAutomaticRebootAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall get_ExtendedError(winrt::hresult*) noexcept = 0;
            virtual int32_t __stdcall GetUpdateItems(void**) noexcept = 0;
            virtual int32_t __stdcall get_AttentionRequiredReason(int32_t*) noexcept = 0;
            virtual int32_t __stdcall SetFlightRing(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall GetFlightRing(void**) noexcept = 0;
            virtual int32_t __stdcall StartInstall(int32_t) noexcept = 0;
            virtual int32_t __stdcall RebootToCompleteInstall() noexcept = 0;
            virtual int32_t __stdcall StartCancelUpdates() noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_System_Update_ISystemUpdateItem
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::System::Update::SystemUpdateItemState) State() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Title() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Description() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Id() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Revision() const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) DownloadProgress() const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) InstallProgress() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::hresult) ExtendedError() const;
    };
    template <> struct consume<winrt::Windows::System::Update::ISystemUpdateItem>
    {
        template <typename D> using type = consume_Windows_System_Update_ISystemUpdateItem<D>;
    };
    template <typename D>
    struct consume_Windows_System_Update_ISystemUpdateLastErrorInfo
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::System::Update::SystemUpdateManagerState) State() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::hresult) ExtendedError() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsInteractive() const;
    };
    template <> struct consume<winrt::Windows::System::Update::ISystemUpdateLastErrorInfo>
    {
        template <typename D> using type = consume_Windows_System_Update_ISystemUpdateLastErrorInfo<D>;
    };
    template <typename D>
    struct consume_Windows_System_Update_ISystemUpdateManagerStatics
    {
        WINRT_IMPL_AUTO(bool) IsSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::System::Update::SystemUpdateManagerState) State() const;
        WINRT_IMPL_AUTO(winrt::event_token) StateChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const;
        using StateChanged_revoker = impl::event_revoker<winrt::Windows::System::Update::ISystemUpdateManagerStatics, &impl::abi_t<winrt::Windows::System::Update::ISystemUpdateManagerStatics>::remove_StateChanged>;
        [[nodiscard]] StateChanged_revoker StateChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) StateChanged(winrt::event_token const& token) const noexcept;
        [[nodiscard]] WINRT_IMPL_AUTO(double) DownloadProgress() const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) InstallProgress() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) UserActiveHoursStart() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) UserActiveHoursEnd() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) UserActiveHoursMax() const;
        WINRT_IMPL_AUTO(bool) TrySetUserActiveHours(winrt::Windows::Foundation::TimeSpan const& start, winrt::Windows::Foundation::TimeSpan const& end) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) LastUpdateCheckTime() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::DateTime) LastUpdateInstallTime() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::System::Update::SystemUpdateLastErrorInfo) LastErrorInfo() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) GetAutomaticRebootBlockIds() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) BlockAutomaticRebootAsync(param::hstring const& lockId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) UnblockAutomaticRebootAsync(param::hstring const& lockId) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::hresult) ExtendedError() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::System::Update::SystemUpdateItem>) GetUpdateItems() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::System::Update::SystemUpdateAttentionRequiredReason) AttentionRequiredReason() const;
        WINRT_IMPL_AUTO(bool) SetFlightRing(param::hstring const& flightRing) const;
        WINRT_IMPL_AUTO(hstring) GetFlightRing() const;
        WINRT_IMPL_AUTO(void) StartInstall(winrt::Windows::System::Update::SystemUpdateStartInstallAction const& action) const;
        WINRT_IMPL_AUTO(void) RebootToCompleteInstall() const;
        WINRT_IMPL_AUTO(void) StartCancelUpdates() const;
    };
    template <> struct consume<winrt::Windows::System::Update::ISystemUpdateManagerStatics>
    {
        template <typename D> using type = consume_Windows_System_Update_ISystemUpdateManagerStatics<D>;
    };
}
#endif
