// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_SerialCommunication_0_H
#define WINRT_Windows_Devices_SerialCommunication_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct EventRegistrationToken;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
}
WINRT_EXPORT namespace winrt::Windows::Storage::Streams
{
    struct IInputStream;
    struct IOutputStream;
}
WINRT_EXPORT namespace winrt::Windows::Devices::SerialCommunication
{
    enum class SerialError : int32_t
    {
        Frame = 0,
        BufferOverrun = 1,
        ReceiveFull = 2,
        ReceiveParity = 3,
        TransmitFull = 4,
    };
    enum class SerialHandshake : int32_t
    {
        None = 0,
        RequestToSend = 1,
        XOnXOff = 2,
        RequestToSendXOnXOff = 3,
    };
    enum class SerialParity : int32_t
    {
        None = 0,
        Odd = 1,
        Even = 2,
        Mark = 3,
        Space = 4,
    };
    enum class SerialPinChange : int32_t
    {
        BreakSignal = 0,
        CarrierDetect = 1,
        ClearToSend = 2,
        DataSetReady = 3,
        RingIndicator = 4,
    };
    enum class SerialStopBitCount : int32_t
    {
        One = 0,
        OnePointFive = 1,
        Two = 2,
    };
    struct IErrorReceivedEventArgs;
    struct IPinChangedEventArgs;
    struct ISerialDevice;
    struct ISerialDeviceStatics;
    struct ErrorReceivedEventArgs;
    struct PinChangedEventArgs;
    struct SerialDevice;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Devices::SerialCommunication::IErrorReceivedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::SerialCommunication::IPinChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::SerialCommunication::ISerialDevice>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::SerialCommunication::ISerialDeviceStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::SerialCommunication::ErrorReceivedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::SerialCommunication::PinChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::SerialCommunication::SerialDevice>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::SerialCommunication::SerialError>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::SerialCommunication::SerialHandshake>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::SerialCommunication::SerialParity>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::SerialCommunication::SerialPinChange>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::SerialCommunication::SerialStopBitCount>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::SerialCommunication::ErrorReceivedEventArgs> = L"Windows.Devices.SerialCommunication.ErrorReceivedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::SerialCommunication::PinChangedEventArgs> = L"Windows.Devices.SerialCommunication.PinChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::SerialCommunication::SerialDevice> = L"Windows.Devices.SerialCommunication.SerialDevice";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::SerialCommunication::SerialError> = L"Windows.Devices.SerialCommunication.SerialError";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::SerialCommunication::SerialHandshake> = L"Windows.Devices.SerialCommunication.SerialHandshake";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::SerialCommunication::SerialParity> = L"Windows.Devices.SerialCommunication.SerialParity";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::SerialCommunication::SerialPinChange> = L"Windows.Devices.SerialCommunication.SerialPinChange";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::SerialCommunication::SerialStopBitCount> = L"Windows.Devices.SerialCommunication.SerialStopBitCount";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::SerialCommunication::IErrorReceivedEventArgs> = L"Windows.Devices.SerialCommunication.IErrorReceivedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::SerialCommunication::IPinChangedEventArgs> = L"Windows.Devices.SerialCommunication.IPinChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::SerialCommunication::ISerialDevice> = L"Windows.Devices.SerialCommunication.ISerialDevice";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::SerialCommunication::ISerialDeviceStatics> = L"Windows.Devices.SerialCommunication.ISerialDeviceStatics";
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::SerialCommunication::IErrorReceivedEventArgs>{ 0xFCC6BF59,0x1283,0x4D8A,{ 0xBF,0xDF,0x56,0x6B,0x33,0xDD,0xB2,0x8F } }; // FCC6BF59-1283-4D8A-BFDF-566B33DDB28F
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::SerialCommunication::IPinChangedEventArgs>{ 0xA2BF1DB0,0xFC9C,0x4607,{ 0x93,0xD0,0xFA,0x5E,0x83,0x43,0xEE,0x22 } }; // A2BF1DB0-FC9C-4607-93D0-FA5E8343EE22
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::SerialCommunication::ISerialDevice>{ 0xE187CCC6,0x2210,0x414F,{ 0xB6,0x5A,0xF5,0x55,0x3A,0x03,0x37,0x2A } }; // E187CCC6-2210-414F-B65A-F5553A03372A
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::SerialCommunication::ISerialDeviceStatics>{ 0x058C4A70,0x0836,0x4993,{ 0xAE,0x1A,0xB6,0x1A,0xE3,0xBE,0x05,0x6B } }; // 058C4A70-0836-4993-AE1A-B61AE3BE056B
    template <> struct default_interface<winrt::Windows::Devices::SerialCommunication::ErrorReceivedEventArgs>{ using type = winrt::Windows::Devices::SerialCommunication::IErrorReceivedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::SerialCommunication::PinChangedEventArgs>{ using type = winrt::Windows::Devices::SerialCommunication::IPinChangedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::SerialCommunication::SerialDevice>{ using type = winrt::Windows::Devices::SerialCommunication::ISerialDevice; };
    template <> struct abi<winrt::Windows::Devices::SerialCommunication::IErrorReceivedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Error(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::SerialCommunication::IPinChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PinChange(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::SerialCommunication::ISerialDevice>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_BaudRate(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_BaudRate(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_BreakSignalState(bool*) noexcept = 0;
            virtual int32_t __stdcall put_BreakSignalState(bool) noexcept = 0;
            virtual int32_t __stdcall get_BytesReceived(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_CarrierDetectState(bool*) noexcept = 0;
            virtual int32_t __stdcall get_ClearToSendState(bool*) noexcept = 0;
            virtual int32_t __stdcall get_DataBits(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall put_DataBits(uint16_t) noexcept = 0;
            virtual int32_t __stdcall get_DataSetReadyState(bool*) noexcept = 0;
            virtual int32_t __stdcall get_Handshake(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_Handshake(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_IsDataTerminalReadyEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsDataTerminalReadyEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall get_IsRequestToSendEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsRequestToSendEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall get_Parity(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_Parity(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_PortName(void**) noexcept = 0;
            virtual int32_t __stdcall get_ReadTimeout(int64_t*) noexcept = 0;
            virtual int32_t __stdcall put_ReadTimeout(int64_t) noexcept = 0;
            virtual int32_t __stdcall get_StopBits(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_StopBits(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_UsbVendorId(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_UsbProductId(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_WriteTimeout(int64_t*) noexcept = 0;
            virtual int32_t __stdcall put_WriteTimeout(int64_t) noexcept = 0;
            virtual int32_t __stdcall get_InputStream(void**) noexcept = 0;
            virtual int32_t __stdcall get_OutputStream(void**) noexcept = 0;
            virtual int32_t __stdcall add_ErrorReceived(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ErrorReceived(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_PinChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_PinChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::SerialCommunication::ISerialDeviceStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDeviceSelector(void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelectorFromPortName(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelectorFromUsbVidPid(uint16_t, uint16_t, void**) noexcept = 0;
            virtual int32_t __stdcall FromIdAsync(void*, void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Devices_SerialCommunication_IErrorReceivedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::SerialCommunication::SerialError) Error() const;
    };
    template <> struct consume<winrt::Windows::Devices::SerialCommunication::IErrorReceivedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_SerialCommunication_IErrorReceivedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_SerialCommunication_IPinChangedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::SerialCommunication::SerialPinChange) PinChange() const;
    };
    template <> struct consume<winrt::Windows::Devices::SerialCommunication::IPinChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_SerialCommunication_IPinChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_SerialCommunication_ISerialDevice
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) BaudRate() const;
        WINRT_IMPL_AUTO(void) BaudRate(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) BreakSignalState() const;
        WINRT_IMPL_AUTO(void) BreakSignalState(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) BytesReceived() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) CarrierDetectState() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ClearToSendState() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) DataBits() const;
        WINRT_IMPL_AUTO(void) DataBits(uint16_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) DataSetReadyState() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::SerialCommunication::SerialHandshake) Handshake() const;
        WINRT_IMPL_AUTO(void) Handshake(winrt::Windows::Devices::SerialCommunication::SerialHandshake const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsDataTerminalReadyEnabled() const;
        WINRT_IMPL_AUTO(void) IsDataTerminalReadyEnabled(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsRequestToSendEnabled() const;
        WINRT_IMPL_AUTO(void) IsRequestToSendEnabled(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::SerialCommunication::SerialParity) Parity() const;
        WINRT_IMPL_AUTO(void) Parity(winrt::Windows::Devices::SerialCommunication::SerialParity const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) PortName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) ReadTimeout() const;
        WINRT_IMPL_AUTO(void) ReadTimeout(winrt::Windows::Foundation::TimeSpan const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::SerialCommunication::SerialStopBitCount) StopBits() const;
        WINRT_IMPL_AUTO(void) StopBits(winrt::Windows::Devices::SerialCommunication::SerialStopBitCount const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) UsbVendorId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) UsbProductId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) WriteTimeout() const;
        WINRT_IMPL_AUTO(void) WriteTimeout(winrt::Windows::Foundation::TimeSpan const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IInputStream) InputStream() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IOutputStream) OutputStream() const;
        WINRT_IMPL_AUTO(winrt::event_token) ErrorReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::SerialCommunication::SerialDevice, winrt::Windows::Devices::SerialCommunication::ErrorReceivedEventArgs> const& reportHandler) const;
        using ErrorReceived_revoker = impl::event_revoker<winrt::Windows::Devices::SerialCommunication::ISerialDevice, &impl::abi_t<winrt::Windows::Devices::SerialCommunication::ISerialDevice>::remove_ErrorReceived>;
        [[nodiscard]] ErrorReceived_revoker ErrorReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::SerialCommunication::SerialDevice, winrt::Windows::Devices::SerialCommunication::ErrorReceivedEventArgs> const& reportHandler) const;
        WINRT_IMPL_AUTO(void) ErrorReceived(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) PinChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::SerialCommunication::SerialDevice, winrt::Windows::Devices::SerialCommunication::PinChangedEventArgs> const& reportHandler) const;
        using PinChanged_revoker = impl::event_revoker<winrt::Windows::Devices::SerialCommunication::ISerialDevice, &impl::abi_t<winrt::Windows::Devices::SerialCommunication::ISerialDevice>::remove_PinChanged>;
        [[nodiscard]] PinChanged_revoker PinChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::SerialCommunication::SerialDevice, winrt::Windows::Devices::SerialCommunication::PinChangedEventArgs> const& reportHandler) const;
        WINRT_IMPL_AUTO(void) PinChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::SerialCommunication::ISerialDevice>
    {
        template <typename D> using type = consume_Windows_Devices_SerialCommunication_ISerialDevice<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_SerialCommunication_ISerialDeviceStatics
    {
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector() const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector(param::hstring const& portName) const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelectorFromUsbVidPid(uint16_t vendorId, uint16_t productId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::SerialCommunication::SerialDevice>) FromIdAsync(param::hstring const& deviceId) const;
    };
    template <> struct consume<winrt::Windows::Devices::SerialCommunication::ISerialDeviceStatics>
    {
        template <typename D> using type = consume_Windows_Devices_SerialCommunication_ISerialDeviceStatics<D>;
    };
}
#endif
