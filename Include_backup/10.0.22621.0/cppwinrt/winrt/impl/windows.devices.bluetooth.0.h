// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_Bluetooth_0_H
#define WINRT_Windows_Devices_Bluetooth_0_H
WINRT_EXPORT namespace winrt::Windows::Devices::Bluetooth::GenericAttributeProfile
{
    struct GattDeviceService;
    struct GattDeviceServicesResult;
}
WINRT_EXPORT namespace winrt::Windows::Devices::Bluetooth::Rfcomm
{
    struct RfcommDeviceService;
    struct RfcommDeviceServicesResult;
    struct RfcommServiceId;
}
WINRT_EXPORT namespace winrt::Windows::Devices::Enumeration
{
    struct DeviceAccessInformation;
    enum class DeviceAccessStatus : int32_t;
    struct DeviceInformation;
}
WINRT_EXPORT namespace winrt::Windows::Devices::Radios
{
    struct Radio;
}
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    struct EventRegistrationToken;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
    template <typename T> struct __declspec(empty_bases) IReference;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IVectorView;
}
WINRT_EXPORT namespace winrt::Windows::Networking
{
    struct HostName;
}
WINRT_EXPORT namespace winrt::Windows::Storage::Streams
{
    struct IBuffer;
}
WINRT_EXPORT namespace winrt::Windows::Devices::Bluetooth
{
    enum class BluetoothAddressType : int32_t
    {
        Public = 0,
        Random = 1,
        Unspecified = 2,
    };
    enum class BluetoothCacheMode : int32_t
    {
        Cached = 0,
        Uncached = 1,
    };
    enum class BluetoothConnectionStatus : int32_t
    {
        Disconnected = 0,
        Connected = 1,
    };
    enum class BluetoothError : int32_t
    {
        Success = 0,
        RadioNotAvailable = 1,
        ResourceInUse = 2,
        DeviceNotConnected = 3,
        OtherError = 4,
        DisabledByPolicy = 5,
        NotSupported = 6,
        DisabledByUser = 7,
        ConsentRequired = 8,
        TransportNotSupported = 9,
    };
    enum class BluetoothLEPreferredConnectionParametersRequestStatus : int32_t
    {
        Unspecified = 0,
        Success = 1,
        DeviceNotAvailable = 2,
        AccessDenied = 3,
    };
    enum class BluetoothMajorClass : int32_t
    {
        Miscellaneous = 0,
        Computer = 1,
        Phone = 2,
        NetworkAccessPoint = 3,
        AudioVideo = 4,
        Peripheral = 5,
        Imaging = 6,
        Wearable = 7,
        Toy = 8,
        Health = 9,
    };
    enum class BluetoothMinorClass : int32_t
    {
        Uncategorized = 0,
        ComputerDesktop = 1,
        ComputerServer = 2,
        ComputerLaptop = 3,
        ComputerHandheld = 4,
        ComputerPalmSize = 5,
        ComputerWearable = 6,
        ComputerTablet = 7,
        PhoneCellular = 1,
        PhoneCordless = 2,
        PhoneSmartPhone = 3,
        PhoneWired = 4,
        PhoneIsdn = 5,
        NetworkFullyAvailable = 0,
        NetworkUsed01To17Percent = 8,
        NetworkUsed17To33Percent = 16,
        NetworkUsed33To50Percent = 24,
        NetworkUsed50To67Percent = 32,
        NetworkUsed67To83Percent = 40,
        NetworkUsed83To99Percent = 48,
        NetworkNoServiceAvailable = 56,
        AudioVideoWearableHeadset = 1,
        AudioVideoHandsFree = 2,
        AudioVideoMicrophone = 4,
        AudioVideoLoudspeaker = 5,
        AudioVideoHeadphones = 6,
        AudioVideoPortableAudio = 7,
        AudioVideoCarAudio = 8,
        AudioVideoSetTopBox = 9,
        AudioVideoHifiAudioDevice = 10,
        AudioVideoVcr = 11,
        AudioVideoVideoCamera = 12,
        AudioVideoCamcorder = 13,
        AudioVideoVideoMonitor = 14,
        AudioVideoVideoDisplayAndLoudspeaker = 15,
        AudioVideoVideoConferencing = 16,
        AudioVideoGamingOrToy = 18,
        PeripheralJoystick = 1,
        PeripheralGamepad = 2,
        PeripheralRemoteControl = 3,
        PeripheralSensing = 4,
        PeripheralDigitizerTablet = 5,
        PeripheralCardReader = 6,
        PeripheralDigitalPen = 7,
        PeripheralHandheldScanner = 8,
        PeripheralHandheldGesture = 9,
        WearableWristwatch = 1,
        WearablePager = 2,
        WearableJacket = 3,
        WearableHelmet = 4,
        WearableGlasses = 5,
        ToyRobot = 1,
        ToyVehicle = 2,
        ToyDoll = 3,
        ToyController = 4,
        ToyGame = 5,
        HealthBloodPressureMonitor = 1,
        HealthThermometer = 2,
        HealthWeighingScale = 3,
        HealthGlucoseMeter = 4,
        HealthPulseOximeter = 5,
        HealthHeartRateMonitor = 6,
        HealthHealthDataDisplay = 7,
        HealthStepCounter = 8,
        HealthBodyCompositionAnalyzer = 9,
        HealthPeakFlowMonitor = 10,
        HealthMedicationMonitor = 11,
        HealthKneeProsthesis = 12,
        HealthAnkleProsthesis = 13,
        HealthGenericHealthManager = 14,
        HealthPersonalMobilityDevice = 15,
    };
    enum class BluetoothServiceCapabilities : uint32_t
    {
        None = 0,
        LimitedDiscoverableMode = 0x1,
        PositioningService = 0x8,
        NetworkingService = 0x10,
        RenderingService = 0x20,
        CapturingService = 0x40,
        ObjectTransferService = 0x80,
        AudioService = 0x100,
        TelephoneService = 0x200,
        InformationService = 0x400,
    };
    struct IBluetoothAdapter;
    struct IBluetoothAdapter2;
    struct IBluetoothAdapter3;
    struct IBluetoothAdapterStatics;
    struct IBluetoothClassOfDevice;
    struct IBluetoothClassOfDeviceStatics;
    struct IBluetoothDevice;
    struct IBluetoothDevice2;
    struct IBluetoothDevice3;
    struct IBluetoothDevice4;
    struct IBluetoothDevice5;
    struct IBluetoothDeviceId;
    struct IBluetoothDeviceIdStatics;
    struct IBluetoothDeviceStatics;
    struct IBluetoothDeviceStatics2;
    struct IBluetoothLEAppearance;
    struct IBluetoothLEAppearanceCategoriesStatics;
    struct IBluetoothLEAppearanceStatics;
    struct IBluetoothLEAppearanceSubcategoriesStatics;
    struct IBluetoothLEConnectionParameters;
    struct IBluetoothLEConnectionPhy;
    struct IBluetoothLEConnectionPhyInfo;
    struct IBluetoothLEDevice;
    struct IBluetoothLEDevice2;
    struct IBluetoothLEDevice3;
    struct IBluetoothLEDevice4;
    struct IBluetoothLEDevice5;
    struct IBluetoothLEDevice6;
    struct IBluetoothLEDeviceStatics;
    struct IBluetoothLEDeviceStatics2;
    struct IBluetoothLEPreferredConnectionParameters;
    struct IBluetoothLEPreferredConnectionParametersRequest;
    struct IBluetoothLEPreferredConnectionParametersStatics;
    struct IBluetoothSignalStrengthFilter;
    struct IBluetoothUuidHelperStatics;
    struct BluetoothAdapter;
    struct BluetoothClassOfDevice;
    struct BluetoothDevice;
    struct BluetoothDeviceId;
    struct BluetoothLEAppearance;
    struct BluetoothLEAppearanceCategories;
    struct BluetoothLEAppearanceSubcategories;
    struct BluetoothLEConnectionParameters;
    struct BluetoothLEConnectionPhy;
    struct BluetoothLEConnectionPhyInfo;
    struct BluetoothLEDevice;
    struct BluetoothLEPreferredConnectionParameters;
    struct BluetoothLEPreferredConnectionParametersRequest;
    struct BluetoothSignalStrengthFilter;
    struct BluetoothUuidHelper;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothAdapter>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothAdapter2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothAdapter3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothAdapterStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothClassOfDevice>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothClassOfDeviceStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothDevice>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothDevice2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothDevice3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothDevice4>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothDevice5>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceId>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceIdStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearance>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionParameters>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionPhy>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionPhyInfo>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice4>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice5>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice6>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParameters>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParametersRequest>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParametersStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothSignalStrengthFilter>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::IBluetoothUuidHelperStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::BluetoothAdapter>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::BluetoothClassOfDevice>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::BluetoothDevice>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::BluetoothDeviceId>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::BluetoothLEAppearance>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::BluetoothLEAppearanceCategories>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::BluetoothLEAppearanceSubcategories>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::BluetoothLEConnectionParameters>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::BluetoothLEConnectionPhy>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::BluetoothLEConnectionPhyInfo>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParameters>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParametersRequest>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::BluetoothSignalStrengthFilter>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::BluetoothUuidHelper>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::BluetoothAddressType>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::BluetoothCacheMode>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::BluetoothConnectionStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::BluetoothError>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParametersRequestStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::BluetoothMajorClass>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::BluetoothMinorClass>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::Bluetooth::BluetoothServiceCapabilities>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::BluetoothAdapter> = L"Windows.Devices.Bluetooth.BluetoothAdapter";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::BluetoothClassOfDevice> = L"Windows.Devices.Bluetooth.BluetoothClassOfDevice";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::BluetoothDevice> = L"Windows.Devices.Bluetooth.BluetoothDevice";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::BluetoothDeviceId> = L"Windows.Devices.Bluetooth.BluetoothDeviceId";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::BluetoothLEAppearance> = L"Windows.Devices.Bluetooth.BluetoothLEAppearance";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::BluetoothLEAppearanceCategories> = L"Windows.Devices.Bluetooth.BluetoothLEAppearanceCategories";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::BluetoothLEAppearanceSubcategories> = L"Windows.Devices.Bluetooth.BluetoothLEAppearanceSubcategories";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::BluetoothLEConnectionParameters> = L"Windows.Devices.Bluetooth.BluetoothLEConnectionParameters";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::BluetoothLEConnectionPhy> = L"Windows.Devices.Bluetooth.BluetoothLEConnectionPhy";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::BluetoothLEConnectionPhyInfo> = L"Windows.Devices.Bluetooth.BluetoothLEConnectionPhyInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice> = L"Windows.Devices.Bluetooth.BluetoothLEDevice";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParameters> = L"Windows.Devices.Bluetooth.BluetoothLEPreferredConnectionParameters";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParametersRequest> = L"Windows.Devices.Bluetooth.BluetoothLEPreferredConnectionParametersRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::BluetoothSignalStrengthFilter> = L"Windows.Devices.Bluetooth.BluetoothSignalStrengthFilter";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::BluetoothUuidHelper> = L"Windows.Devices.Bluetooth.BluetoothUuidHelper";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::BluetoothAddressType> = L"Windows.Devices.Bluetooth.BluetoothAddressType";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::BluetoothCacheMode> = L"Windows.Devices.Bluetooth.BluetoothCacheMode";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::BluetoothConnectionStatus> = L"Windows.Devices.Bluetooth.BluetoothConnectionStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::BluetoothError> = L"Windows.Devices.Bluetooth.BluetoothError";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParametersRequestStatus> = L"Windows.Devices.Bluetooth.BluetoothLEPreferredConnectionParametersRequestStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::BluetoothMajorClass> = L"Windows.Devices.Bluetooth.BluetoothMajorClass";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::BluetoothMinorClass> = L"Windows.Devices.Bluetooth.BluetoothMinorClass";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::BluetoothServiceCapabilities> = L"Windows.Devices.Bluetooth.BluetoothServiceCapabilities";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothAdapter> = L"Windows.Devices.Bluetooth.IBluetoothAdapter";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothAdapter2> = L"Windows.Devices.Bluetooth.IBluetoothAdapter2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothAdapter3> = L"Windows.Devices.Bluetooth.IBluetoothAdapter3";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothAdapterStatics> = L"Windows.Devices.Bluetooth.IBluetoothAdapterStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothClassOfDevice> = L"Windows.Devices.Bluetooth.IBluetoothClassOfDevice";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothClassOfDeviceStatics> = L"Windows.Devices.Bluetooth.IBluetoothClassOfDeviceStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothDevice> = L"Windows.Devices.Bluetooth.IBluetoothDevice";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothDevice2> = L"Windows.Devices.Bluetooth.IBluetoothDevice2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothDevice3> = L"Windows.Devices.Bluetooth.IBluetoothDevice3";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothDevice4> = L"Windows.Devices.Bluetooth.IBluetoothDevice4";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothDevice5> = L"Windows.Devices.Bluetooth.IBluetoothDevice5";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceId> = L"Windows.Devices.Bluetooth.IBluetoothDeviceId";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceIdStatics> = L"Windows.Devices.Bluetooth.IBluetoothDeviceIdStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceStatics> = L"Windows.Devices.Bluetooth.IBluetoothDeviceStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceStatics2> = L"Windows.Devices.Bluetooth.IBluetoothDeviceStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearance> = L"Windows.Devices.Bluetooth.IBluetoothLEAppearance";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics> = L"Windows.Devices.Bluetooth.IBluetoothLEAppearanceCategoriesStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceStatics> = L"Windows.Devices.Bluetooth.IBluetoothLEAppearanceStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics> = L"Windows.Devices.Bluetooth.IBluetoothLEAppearanceSubcategoriesStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionParameters> = L"Windows.Devices.Bluetooth.IBluetoothLEConnectionParameters";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionPhy> = L"Windows.Devices.Bluetooth.IBluetoothLEConnectionPhy";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionPhyInfo> = L"Windows.Devices.Bluetooth.IBluetoothLEConnectionPhyInfo";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice> = L"Windows.Devices.Bluetooth.IBluetoothLEDevice";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice2> = L"Windows.Devices.Bluetooth.IBluetoothLEDevice2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice3> = L"Windows.Devices.Bluetooth.IBluetoothLEDevice3";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice4> = L"Windows.Devices.Bluetooth.IBluetoothLEDevice4";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice5> = L"Windows.Devices.Bluetooth.IBluetoothLEDevice5";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice6> = L"Windows.Devices.Bluetooth.IBluetoothLEDevice6";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics> = L"Windows.Devices.Bluetooth.IBluetoothLEDeviceStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2> = L"Windows.Devices.Bluetooth.IBluetoothLEDeviceStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParameters> = L"Windows.Devices.Bluetooth.IBluetoothLEPreferredConnectionParameters";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParametersRequest> = L"Windows.Devices.Bluetooth.IBluetoothLEPreferredConnectionParametersRequest";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParametersStatics> = L"Windows.Devices.Bluetooth.IBluetoothLEPreferredConnectionParametersStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothSignalStrengthFilter> = L"Windows.Devices.Bluetooth.IBluetoothSignalStrengthFilter";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::Bluetooth::IBluetoothUuidHelperStatics> = L"Windows.Devices.Bluetooth.IBluetoothUuidHelperStatics";
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothAdapter>{ 0x7974F04C,0x5F7A,0x4A34,{ 0x92,0x25,0xA8,0x55,0xF8,0x4B,0x1A,0x8B } }; // 7974F04C-5F7A-4A34-9225-A855F84B1A8B
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothAdapter2>{ 0xAC94CECC,0x24D5,0x41B3,{ 0x91,0x6D,0x10,0x97,0xC5,0x0B,0x10,0x2B } }; // AC94CECC-24D5-41B3-916D-1097C50B102B
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothAdapter3>{ 0x8F8624E0,0xCBA9,0x5211,{ 0x9F,0x89,0x3A,0xAC,0x62,0xB4,0xC6,0xB8 } }; // 8F8624E0-CBA9-5211-9F89-3AAC62B4C6B8
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothAdapterStatics>{ 0x8B02FB6A,0xAC4C,0x4741,{ 0x86,0x61,0x8E,0xAB,0x7D,0x17,0xEA,0x9F } }; // 8B02FB6A-AC4C-4741-8661-8EAB7D17EA9F
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothClassOfDevice>{ 0xD640227E,0xD7D7,0x4661,{ 0x94,0x54,0x65,0x03,0x9C,0xA1,0x7A,0x2B } }; // D640227E-D7D7-4661-9454-65039CA17A2B
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothClassOfDeviceStatics>{ 0xE46135BD,0x0FA2,0x416C,{ 0x91,0xB4,0xC1,0xE4,0x8C,0xA0,0x61,0xC1 } }; // E46135BD-0FA2-416C-91B4-C1E48CA061C1
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothDevice>{ 0x2335B156,0x90D2,0x4A04,{ 0xAE,0xF5,0x0E,0x20,0xB9,0xE6,0xB7,0x07 } }; // 2335B156-90D2-4A04-AEF5-0E20B9E6B707
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothDevice2>{ 0x0133F954,0xB156,0x4DD0,{ 0xB1,0xF5,0xC1,0x1B,0xC3,0x1A,0x51,0x63 } }; // 0133F954-B156-4DD0-B1F5-C11BC31A5163
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothDevice3>{ 0x57FFF78B,0x651A,0x4454,{ 0xB9,0x0F,0xEB,0x21,0xEF,0x0B,0x0D,0x71 } }; // 57FFF78B-651A-4454-B90F-EB21EF0B0D71
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothDevice4>{ 0x817C34AD,0x0E9C,0x42B2,{ 0xA8,0xDC,0x3E,0x80,0x94,0x94,0x0D,0x12 } }; // 817C34AD-0E9C-42B2-A8DC-3E8094940D12
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothDevice5>{ 0xB5E0B385,0x5E85,0x4559,{ 0xA1,0x0D,0x1C,0x72,0x81,0x37,0x9F,0x96 } }; // B5E0B385-5E85-4559-A10D-1C7281379F96
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceId>{ 0xC17949AF,0x57C1,0x4642,{ 0xBC,0xCE,0xE6,0xC0,0x6B,0x20,0xAE,0x76 } }; // C17949AF-57C1-4642-BCCE-E6C06B20AE76
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceIdStatics>{ 0xA7884E67,0x3EFB,0x4F31,{ 0xBB,0xC2,0x81,0x0E,0x09,0x97,0x74,0x04 } }; // A7884E67-3EFB-4F31-BBC2-810E09977404
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceStatics>{ 0x0991DF51,0x57DB,0x4725,{ 0xBB,0xD7,0x84,0xF6,0x43,0x27,0xEC,0x2C } }; // 0991DF51-57DB-4725-BBD7-84F64327EC2C
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceStatics2>{ 0xC29E8E2F,0x4E14,0x4477,{ 0xAA,0x1B,0xB8,0xB4,0x7E,0x5B,0x7E,0xCE } }; // C29E8E2F-4E14-4477-AA1B-B8B47E5B7ECE
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearance>{ 0x5D2079F2,0x66A8,0x4258,{ 0x98,0x5E,0x02,0xB4,0xD9,0x50,0x9F,0x18 } }; // 5D2079F2-66A8-4258-985E-02B4D9509F18
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics>{ 0x6D4D54FE,0x046A,0x4185,{ 0xAA,0xB6,0x82,0x4C,0xF0,0x61,0x08,0x61 } }; // 6D4D54FE-046A-4185-AAB6-824CF0610861
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceStatics>{ 0xA193C0C7,0x4504,0x4F4A,{ 0x9B,0xA5,0xCD,0x10,0x54,0xE5,0xE0,0x65 } }; // A193C0C7-4504-4F4A-9BA5-CD1054E5E065
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>{ 0xE57BA606,0x2144,0x415A,{ 0x83,0x12,0x71,0xCC,0xF2,0x91,0xF8,0xD1 } }; // E57BA606-2144-415A-8312-71CCF291F8D1
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionParameters>{ 0x33CB0771,0x8DA9,0x508F,{ 0xA3,0x66,0x1C,0xA3,0x88,0xC9,0x29,0xAB } }; // 33CB0771-8DA9-508F-A366-1CA388C929AB
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionPhy>{ 0x781E5E48,0x621E,0x5A7E,{ 0x8B,0xE6,0x1B,0x95,0x61,0xFF,0x63,0xC9 } }; // 781E5E48-621E-5A7E-8BE6-1B9561FF63C9
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionPhyInfo>{ 0x9A100BDD,0x602E,0x5C27,{ 0xA1,0xAE,0xB2,0x30,0x01,0x5A,0x63,0x94 } }; // 9A100BDD-602E-5C27-A1AE-B230015A6394
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice>{ 0xB5EE2F7B,0x4AD8,0x4642,{ 0xAC,0x48,0x80,0xA0,0xB5,0x00,0xE8,0x87 } }; // B5EE2F7B-4AD8-4642-AC48-80A0B500E887
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice2>{ 0x26F062B3,0x7AEE,0x4D31,{ 0xBA,0xBA,0xB1,0xB9,0x77,0x5F,0x59,0x16 } }; // 26F062B3-7AEE-4D31-BABA-B1B9775F5916
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice3>{ 0xAEE9E493,0x44AC,0x40DC,{ 0xAF,0x33,0xB2,0xC1,0x3C,0x01,0xCA,0x46 } }; // AEE9E493-44AC-40DC-AF33-B2C13C01CA46
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice4>{ 0x2B605031,0x2248,0x4B2F,{ 0xAC,0xF0,0x7C,0xEE,0x36,0xFC,0x58,0x70 } }; // 2B605031-2248-4B2F-ACF0-7CEE36FC5870
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice5>{ 0x9D6A1260,0x5287,0x458E,{ 0x95,0xBA,0x17,0xC8,0xB7,0xBB,0x32,0x6E } }; // 9D6A1260-5287-458E-95BA-17C8B7BB326E
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice6>{ 0xCA7190EF,0x0CAE,0x573C,{ 0xA1,0xCA,0xE1,0xFC,0x5B,0xFC,0x39,0xE2 } }; // CA7190EF-0CAE-573C-A1CA-E1FC5BFC39E2
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics>{ 0xC8CF1A19,0xF0B6,0x4BF0,{ 0x86,0x89,0x41,0x30,0x3D,0xE2,0xD9,0xF4 } }; // C8CF1A19-F0B6-4BF0-8689-41303DE2D9F4
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2>{ 0x5F12C06B,0x3BAC,0x43E8,{ 0xAD,0x16,0x56,0x32,0x71,0xBD,0x41,0xC2 } }; // 5F12C06B-3BAC-43E8-AD16-563271BD41C2
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParameters>{ 0xF2F44344,0x7372,0x5F7B,{ 0x9B,0x34,0x29,0xC9,0x44,0xF5,0xA7,0x15 } }; // F2F44344-7372-5F7B-9B34-29C944F5A715
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParametersRequest>{ 0x8A375276,0xA528,0x5266,{ 0xB6,0x61,0xCC,0xE6,0xA5,0xFF,0x97,0x39 } }; // 8A375276-A528-5266-B661-CCE6A5FF9739
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParametersStatics>{ 0x0E3E8EDC,0x2751,0x55AA,{ 0xA8,0x38,0x8F,0xAE,0xEE,0x81,0x8D,0x72 } }; // 0E3E8EDC-2751-55AA-A838-8FAEEE818D72
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothSignalStrengthFilter>{ 0xDF7B7391,0x6BB5,0x4CFE,{ 0x90,0xB1,0x5D,0x73,0x24,0xED,0xCF,0x7F } }; // DF7B7391-6BB5-4CFE-90B1-5D7324EDCF7F
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::Bluetooth::IBluetoothUuidHelperStatics>{ 0x17DF0CD8,0xCF74,0x4B21,{ 0xAF,0xE6,0xF5,0x7A,0x11,0xBC,0xDE,0xA0 } }; // 17DF0CD8-CF74-4B21-AFE6-F57A11BCDEA0
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::BluetoothAdapter>{ using type = winrt::Windows::Devices::Bluetooth::IBluetoothAdapter; };
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::BluetoothClassOfDevice>{ using type = winrt::Windows::Devices::Bluetooth::IBluetoothClassOfDevice; };
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::BluetoothDevice>{ using type = winrt::Windows::Devices::Bluetooth::IBluetoothDevice; };
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::BluetoothDeviceId>{ using type = winrt::Windows::Devices::Bluetooth::IBluetoothDeviceId; };
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::BluetoothLEAppearance>{ using type = winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearance; };
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::BluetoothLEConnectionParameters>{ using type = winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionParameters; };
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::BluetoothLEConnectionPhy>{ using type = winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionPhy; };
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::BluetoothLEConnectionPhyInfo>{ using type = winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionPhyInfo; };
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice>{ using type = winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice; };
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParameters>{ using type = winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParameters; };
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParametersRequest>{ using type = winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParametersRequest; };
    template <> struct default_interface<winrt::Windows::Devices::Bluetooth::BluetoothSignalStrengthFilter>{ using type = winrt::Windows::Devices::Bluetooth::IBluetoothSignalStrengthFilter; };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothAdapter>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
            virtual int32_t __stdcall get_BluetoothAddress(uint64_t*) noexcept = 0;
            virtual int32_t __stdcall get_IsClassicSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsLowEnergySupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsPeripheralRoleSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsCentralRoleSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsAdvertisementOffloadSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall GetRadioAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothAdapter2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AreClassicSecureConnectionsSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_AreLowEnergySecureConnectionsSupported(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothAdapter3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsExtendedAdvertisingSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_MaxAdvertisementDataLength(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothAdapterStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDeviceSelector(void**) noexcept = 0;
            virtual int32_t __stdcall FromIdAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetDefaultAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothClassOfDevice>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_RawValue(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_MajorClass(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_MinorClass(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ServiceCapabilities(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothClassOfDeviceStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall FromRawValue(uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall FromParts(int32_t, int32_t, uint32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothDevice>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
            virtual int32_t __stdcall get_HostName(void**) noexcept = 0;
            virtual int32_t __stdcall get_Name(void**) noexcept = 0;
            virtual int32_t __stdcall get_ClassOfDevice(void**) noexcept = 0;
            virtual int32_t __stdcall get_SdpRecords(void**) noexcept = 0;
            virtual int32_t __stdcall get_RfcommServices(void**) noexcept = 0;
            virtual int32_t __stdcall get_ConnectionStatus(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_BluetoothAddress(uint64_t*) noexcept = 0;
            virtual int32_t __stdcall add_NameChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_NameChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_SdpRecordsChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_SdpRecordsChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ConnectionStatusChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ConnectionStatusChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothDevice2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceInformation(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothDevice3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceAccessInformation(void**) noexcept = 0;
            virtual int32_t __stdcall RequestAccessAsync(void**) noexcept = 0;
            virtual int32_t __stdcall GetRfcommServicesAsync(void**) noexcept = 0;
            virtual int32_t __stdcall GetRfcommServicesWithCacheModeAsync(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetRfcommServicesForIdAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetRfcommServicesForIdWithCacheModeAsync(void*, int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothDevice4>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_BluetoothDeviceId(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothDevice5>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_WasSecureConnectionUsedForPairing(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceId>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Id(void**) noexcept = 0;
            virtual int32_t __stdcall get_IsClassicDevice(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsLowEnergyDevice(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceIdStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall FromId(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall FromIdAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall FromHostNameAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall FromBluetoothAddressAsync(uint64_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelector(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDeviceSelectorFromPairingState(bool, void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelectorFromConnectionStatus(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelectorFromDeviceName(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelectorFromBluetoothAddress(uint64_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelectorFromClassOfDevice(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearance>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_RawValue(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_Category(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_SubCategory(uint16_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Uncategorized(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_Phone(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_Computer(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_Watch(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_Clock(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_Display(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_RemoteControl(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_EyeGlasses(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_Tag(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_Keyring(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_MediaPlayer(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_BarcodeScanner(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_Thermometer(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_HeartRate(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_BloodPressure(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_HumanInterfaceDevice(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_GlucoseMeter(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_RunningWalking(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_Cycling(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_PulseOximeter(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_WeightScale(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_OutdoorSportActivity(uint16_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall FromRawValue(uint16_t, void**) noexcept = 0;
            virtual int32_t __stdcall FromParts(uint16_t, uint16_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Generic(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_SportsWatch(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_ThermometerEar(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_HeartRateBelt(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_BloodPressureArm(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_BloodPressureWrist(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_Keyboard(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_Mouse(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_Joystick(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_Gamepad(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_DigitizerTablet(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_CardReader(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_DigitalPen(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_BarcodeScanner(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_RunningWalkingInShoe(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_RunningWalkingOnShoe(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_RunningWalkingOnHip(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_CyclingComputer(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_CyclingSpeedSensor(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_CyclingCadenceSensor(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_CyclingPowerSensor(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_CyclingSpeedCadenceSensor(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_OximeterFingertip(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_OximeterWristWorn(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_LocationDisplay(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_LocationNavigationDisplay(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_LocationPod(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_LocationNavigationPod(uint16_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionParameters>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_LinkTimeout(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_ConnectionLatency(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_ConnectionInterval(uint16_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionPhy>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_TransmitInfo(void**) noexcept = 0;
            virtual int32_t __stdcall get_ReceiveInfo(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionPhyInfo>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsUncoded1MPhy(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsUncoded2MPhy(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsCodedPhy(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
            virtual int32_t __stdcall get_Name(void**) noexcept = 0;
            virtual int32_t __stdcall get_GattServices(void**) noexcept = 0;
            virtual int32_t __stdcall get_ConnectionStatus(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_BluetoothAddress(uint64_t*) noexcept = 0;
            virtual int32_t __stdcall GetGattService(winrt::guid, void**) noexcept = 0;
            virtual int32_t __stdcall add_NameChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_NameChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_GattServicesChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_GattServicesChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ConnectionStatusChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ConnectionStatusChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceInformation(void**) noexcept = 0;
            virtual int32_t __stdcall get_Appearance(void**) noexcept = 0;
            virtual int32_t __stdcall get_BluetoothAddressType(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceAccessInformation(void**) noexcept = 0;
            virtual int32_t __stdcall RequestAccessAsync(void**) noexcept = 0;
            virtual int32_t __stdcall GetGattServicesAsync(void**) noexcept = 0;
            virtual int32_t __stdcall GetGattServicesWithCacheModeAsync(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetGattServicesForUuidAsync(winrt::guid, void**) noexcept = 0;
            virtual int32_t __stdcall GetGattServicesForUuidWithCacheModeAsync(winrt::guid, int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice4>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_BluetoothDeviceId(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice5>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_WasSecureConnectionUsedForPairing(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice6>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetConnectionParameters(void**) noexcept = 0;
            virtual int32_t __stdcall GetConnectionPhy(void**) noexcept = 0;
            virtual int32_t __stdcall RequestPreferredConnectionParameters(void*, void**) noexcept = 0;
            virtual int32_t __stdcall add_ConnectionParametersChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ConnectionParametersChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ConnectionPhyChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ConnectionPhyChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall FromIdAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall FromBluetoothAddressAsync(uint64_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelector(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDeviceSelectorFromPairingState(bool, void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelectorFromConnectionStatus(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelectorFromDeviceName(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelectorFromBluetoothAddress(uint64_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelectorFromBluetoothAddressWithBluetoothAddressType(uint64_t, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelectorFromAppearance(void*, void**) noexcept = 0;
            virtual int32_t __stdcall FromBluetoothAddressWithBluetoothAddressTypeAsync(uint64_t, int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParameters>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_LinkTimeout(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_ConnectionLatency(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_MinConnectionInterval(uint16_t*) noexcept = 0;
            virtual int32_t __stdcall get_MaxConnectionInterval(uint16_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParametersRequest>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParametersStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Balanced(void**) noexcept = 0;
            virtual int32_t __stdcall get_ThroughputOptimized(void**) noexcept = 0;
            virtual int32_t __stdcall get_PowerOptimized(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothSignalStrengthFilter>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_InRangeThresholdInDBm(void**) noexcept = 0;
            virtual int32_t __stdcall put_InRangeThresholdInDBm(void*) noexcept = 0;
            virtual int32_t __stdcall get_OutOfRangeThresholdInDBm(void**) noexcept = 0;
            virtual int32_t __stdcall put_OutOfRangeThresholdInDBm(void*) noexcept = 0;
            virtual int32_t __stdcall get_OutOfRangeTimeout(void**) noexcept = 0;
            virtual int32_t __stdcall put_OutOfRangeTimeout(void*) noexcept = 0;
            virtual int32_t __stdcall get_SamplingInterval(void**) noexcept = 0;
            virtual int32_t __stdcall put_SamplingInterval(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::Bluetooth::IBluetoothUuidHelperStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall FromShortId(uint32_t, winrt::guid*) noexcept = 0;
            virtual int32_t __stdcall TryGetShortId(winrt::guid, void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothAdapter
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint64_t) BluetoothAddress() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsClassicSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsLowEnergySupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsPeripheralRoleSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsCentralRoleSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsAdvertisementOffloadSupported() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Radios::Radio>) GetRadioAsync() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothAdapter>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothAdapter<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothAdapter2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AreClassicSecureConnectionsSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AreLowEnergySecureConnectionsSupported() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothAdapter2>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothAdapter2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothAdapter3
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsExtendedAdvertisingSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MaxAdvertisementDataLength() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothAdapter3>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothAdapter3<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothAdapterStatics
    {
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothAdapter>) FromIdAsync(param::hstring const& deviceId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothAdapter>) GetDefaultAsync() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothAdapterStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothAdapterStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothClassOfDevice
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) RawValue() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothMajorClass) MajorClass() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothMinorClass) MinorClass() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothServiceCapabilities) ServiceCapabilities() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothClassOfDevice>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothClassOfDevice<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothClassOfDeviceStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothClassOfDevice) FromRawValue(uint32_t rawValue) const;
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothClassOfDevice) FromParts(winrt::Windows::Devices::Bluetooth::BluetoothMajorClass const& majorClass, winrt::Windows::Devices::Bluetooth::BluetoothMinorClass const& minorClass, winrt::Windows::Devices::Bluetooth::BluetoothServiceCapabilities const& serviceCapabilities) const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothClassOfDeviceStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothClassOfDeviceStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothDevice
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Networking::HostName) HostName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Name() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothClassOfDevice) ClassOfDevice() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Storage::Streams::IBuffer>) SdpRecords() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceService>) RfcommServices() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothConnectionStatus) ConnectionStatus() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint64_t) BluetoothAddress() const;
        WINRT_IMPL_AUTO(winrt::event_token) NameChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothDevice, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using NameChanged_revoker = impl::event_revoker<winrt::Windows::Devices::Bluetooth::IBluetoothDevice, &impl::abi_t<winrt::Windows::Devices::Bluetooth::IBluetoothDevice>::remove_NameChanged>;
        [[nodiscard]] NameChanged_revoker NameChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothDevice, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) NameChanged(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) SdpRecordsChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothDevice, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using SdpRecordsChanged_revoker = impl::event_revoker<winrt::Windows::Devices::Bluetooth::IBluetoothDevice, &impl::abi_t<winrt::Windows::Devices::Bluetooth::IBluetoothDevice>::remove_SdpRecordsChanged>;
        [[nodiscard]] SdpRecordsChanged_revoker SdpRecordsChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothDevice, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) SdpRecordsChanged(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ConnectionStatusChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothDevice, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using ConnectionStatusChanged_revoker = impl::event_revoker<winrt::Windows::Devices::Bluetooth::IBluetoothDevice, &impl::abi_t<winrt::Windows::Devices::Bluetooth::IBluetoothDevice>::remove_ConnectionStatusChanged>;
        [[nodiscard]] ConnectionStatusChanged_revoker ConnectionStatusChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothDevice, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) ConnectionStatusChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothDevice>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothDevice<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothDevice2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceInformation) DeviceInformation() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothDevice2>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothDevice2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothDevice3
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceAccessInformation) DeviceAccessInformation() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceAccessStatus>) RequestAccessAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult>) GetRfcommServicesAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult>) GetRfcommServicesAsync(winrt::Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult>) GetRfcommServicesForIdAsync(winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const& serviceId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommDeviceServicesResult>) GetRfcommServicesForIdAsync(winrt::Windows::Devices::Bluetooth::Rfcomm::RfcommServiceId const& serviceId, winrt::Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothDevice3>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothDevice3<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothDevice4
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothDeviceId) BluetoothDeviceId() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothDevice4>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothDevice4<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothDevice5
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) WasSecureConnectionUsedForPairing() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothDevice5>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothDevice5<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothDeviceId
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Id() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsClassicDevice() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsLowEnergyDevice() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceId>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothDeviceId<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothDeviceIdStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothDeviceId) FromId(param::hstring const& deviceId) const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceIdStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothDeviceIdStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothDeviceStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothDevice>) FromIdAsync(param::hstring const& deviceId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothDevice>) FromHostNameAsync(winrt::Windows::Networking::HostName const& hostName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothDevice>) FromBluetoothAddressAsync(uint64_t address) const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothDeviceStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothDeviceStatics2
    {
        WINRT_IMPL_AUTO(hstring) GetDeviceSelectorFromPairingState(bool pairingState) const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelectorFromConnectionStatus(winrt::Windows::Devices::Bluetooth::BluetoothConnectionStatus const& connectionStatus) const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelectorFromDeviceName(param::hstring const& deviceName) const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelectorFromBluetoothAddress(uint64_t bluetoothAddress) const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelectorFromClassOfDevice(winrt::Windows::Devices::Bluetooth::BluetoothClassOfDevice const& classOfDevice) const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothDeviceStatics2>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothDeviceStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothLEAppearance
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) RawValue() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) Category() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) SubCategory() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearance>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothLEAppearance<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) Uncategorized() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) Phone() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) Computer() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) Watch() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) Clock() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) Display() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) RemoteControl() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) EyeGlasses() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) Tag() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) Keyring() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) MediaPlayer() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) BarcodeScanner() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) Thermometer() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) HeartRate() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) BloodPressure() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) HumanInterfaceDevice() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) GlucoseMeter() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) RunningWalking() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) Cycling() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) PulseOximeter() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) WeightScale() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) OutdoorSportActivity() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceCategoriesStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceCategoriesStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothLEAppearance) FromRawValue(uint16_t rawValue) const;
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothLEAppearance) FromParts(uint16_t appearanceCategory, uint16_t appearanceSubCategory) const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) Generic() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) SportsWatch() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) ThermometerEar() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) HeartRateBelt() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) BloodPressureArm() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) BloodPressureWrist() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) Keyboard() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) Mouse() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) Joystick() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) Gamepad() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) DigitizerTablet() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) CardReader() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) DigitalPen() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) BarcodeScanner() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) RunningWalkingInShoe() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) RunningWalkingOnShoe() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) RunningWalkingOnHip() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) CyclingComputer() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) CyclingSpeedSensor() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) CyclingCadenceSensor() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) CyclingPowerSensor() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) CyclingSpeedCadenceSensor() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) OximeterFingertip() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) OximeterWristWorn() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) LocationDisplay() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) LocationNavigationDisplay() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) LocationPod() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) LocationNavigationPod() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothLEAppearanceSubcategoriesStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothLEAppearanceSubcategoriesStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothLEConnectionParameters
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) LinkTimeout() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) ConnectionLatency() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) ConnectionInterval() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionParameters>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothLEConnectionParameters<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothLEConnectionPhy
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothLEConnectionPhyInfo) TransmitInfo() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothLEConnectionPhyInfo) ReceiveInfo() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionPhy>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothLEConnectionPhy<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothLEConnectionPhyInfo
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsUncoded1MPhy() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsUncoded2MPhy() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsCodedPhy() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothLEConnectionPhyInfo>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothLEConnectionPhyInfo<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothLEDevice
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Name() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService>) GattServices() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothConnectionStatus) ConnectionStatus() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint64_t) BluetoothAddress() const;
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceService) GetGattService(winrt::guid const& serviceUuid) const;
        WINRT_IMPL_AUTO(winrt::event_token) NameChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using NameChanged_revoker = impl::event_revoker<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice, &impl::abi_t<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice>::remove_NameChanged>;
        [[nodiscard]] NameChanged_revoker NameChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) NameChanged(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) GattServicesChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using GattServicesChanged_revoker = impl::event_revoker<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice, &impl::abi_t<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice>::remove_GattServicesChanged>;
        [[nodiscard]] GattServicesChanged_revoker GattServicesChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) GattServicesChanged(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ConnectionStatusChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using ConnectionStatusChanged_revoker = impl::event_revoker<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice, &impl::abi_t<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice>::remove_ConnectionStatusChanged>;
        [[nodiscard]] ConnectionStatusChanged_revoker ConnectionStatusChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) ConnectionStatusChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothLEDevice<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothLEDevice2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceInformation) DeviceInformation() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothLEAppearance) Appearance() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothAddressType) BluetoothAddressType() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice2>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothLEDevice2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothLEDevice3
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Enumeration::DeviceAccessInformation) DeviceAccessInformation() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Enumeration::DeviceAccessStatus>) RequestAccessAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>) GetGattServicesAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>) GetGattServicesAsync(winrt::Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>) GetGattServicesForUuidAsync(winrt::guid const& serviceUuid) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult>) GetGattServicesForUuidAsync(winrt::guid const& serviceUuid, winrt::Windows::Devices::Bluetooth::BluetoothCacheMode const& cacheMode) const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice3>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothLEDevice3<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothLEDevice4
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothDeviceId) BluetoothDeviceId() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice4>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothLEDevice4<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothLEDevice5
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) WasSecureConnectionUsedForPairing() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice5>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothLEDevice5<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothLEDevice6
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothLEConnectionParameters) GetConnectionParameters() const;
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothLEConnectionPhy) GetConnectionPhy() const;
        WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParametersRequest) RequestPreferredConnectionParameters(winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParameters const& preferredConnectionParameters) const;
        WINRT_IMPL_AUTO(winrt::event_token) ConnectionParametersChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using ConnectionParametersChanged_revoker = impl::event_revoker<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice6, &impl::abi_t<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice6>::remove_ConnectionParametersChanged>;
        [[nodiscard]] ConnectionParametersChanged_revoker ConnectionParametersChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) ConnectionParametersChanged(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ConnectionPhyChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using ConnectionPhyChanged_revoker = impl::event_revoker<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice6, &impl::abi_t<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice6>::remove_ConnectionPhyChanged>;
        [[nodiscard]] ConnectionPhyChanged_revoker ConnectionPhyChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) ConnectionPhyChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothLEDevice6>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothLEDevice6<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothLEDeviceStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice>) FromIdAsync(param::hstring const& deviceId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice>) FromBluetoothAddressAsync(uint64_t bluetoothAddress) const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothLEDeviceStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothLEDeviceStatics2
    {
        WINRT_IMPL_AUTO(hstring) GetDeviceSelectorFromPairingState(bool pairingState) const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelectorFromConnectionStatus(winrt::Windows::Devices::Bluetooth::BluetoothConnectionStatus const& connectionStatus) const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelectorFromDeviceName(param::hstring const& deviceName) const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelectorFromBluetoothAddress(uint64_t bluetoothAddress) const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelectorFromBluetoothAddress(uint64_t bluetoothAddress, winrt::Windows::Devices::Bluetooth::BluetoothAddressType const& bluetoothAddressType) const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelectorFromAppearance(winrt::Windows::Devices::Bluetooth::BluetoothLEAppearance const& appearance) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::Bluetooth::BluetoothLEDevice>) FromBluetoothAddressAsync(uint64_t bluetoothAddress, winrt::Windows::Devices::Bluetooth::BluetoothAddressType const& bluetoothAddressType) const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothLEDeviceStatics2>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothLEDeviceStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothLEPreferredConnectionParameters
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) LinkTimeout() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) ConnectionLatency() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) MinConnectionInterval() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint16_t) MaxConnectionInterval() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParameters>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothLEPreferredConnectionParameters<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothLEPreferredConnectionParametersRequest
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParametersRequestStatus) Status() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParametersRequest>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothLEPreferredConnectionParametersRequest<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothLEPreferredConnectionParametersStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParameters) Balanced() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParameters) ThroughputOptimized() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::Bluetooth::BluetoothLEPreferredConnectionParameters) PowerOptimized() const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothLEPreferredConnectionParametersStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothLEPreferredConnectionParametersStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothSignalStrengthFilter
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int16_t>) InRangeThresholdInDBm() const;
        WINRT_IMPL_AUTO(void) InRangeThresholdInDBm(winrt::Windows::Foundation::IReference<int16_t> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<int16_t>) OutOfRangeThresholdInDBm() const;
        WINRT_IMPL_AUTO(void) OutOfRangeThresholdInDBm(winrt::Windows::Foundation::IReference<int16_t> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) OutOfRangeTimeout() const;
        WINRT_IMPL_AUTO(void) OutOfRangeTimeout(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan>) SamplingInterval() const;
        WINRT_IMPL_AUTO(void) SamplingInterval(winrt::Windows::Foundation::IReference<winrt::Windows::Foundation::TimeSpan> const& value) const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothSignalStrengthFilter>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothSignalStrengthFilter<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_Bluetooth_IBluetoothUuidHelperStatics
    {
        WINRT_IMPL_AUTO(winrt::guid) FromShortId(uint32_t shortId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<uint32_t>) TryGetShortId(winrt::guid const& uuid) const;
    };
    template <> struct consume<winrt::Windows::Devices::Bluetooth::IBluetoothUuidHelperStatics>
    {
        template <typename D> using type = consume_Windows_Devices_Bluetooth_IBluetoothUuidHelperStatics<D>;
    };
}
#endif
