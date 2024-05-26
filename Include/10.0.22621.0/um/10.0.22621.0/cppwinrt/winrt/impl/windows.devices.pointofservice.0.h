// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Devices_PointOfService_0_H
#define WINRT_Windows_Devices_PointOfService_0_H
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    template <typename T> struct __declspec(empty_bases) EventHandler;
    struct EventRegistrationToken;
    struct IAsyncAction;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
    struct Point;
    struct Rect;
    struct Size;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IIterable;
    template <typename K, typename V> struct __declspec(empty_bases) IKeyValuePair;
    template <typename K, typename V> struct __declspec(empty_bases) IMapView;
    template <typename T> struct __declspec(empty_bases) IVectorView;
}
WINRT_EXPORT namespace winrt::Windows::Graphics::Imaging
{
    struct BitmapFrame;
}
WINRT_EXPORT namespace winrt::Windows::Storage
{
    struct StorageFile;
}
WINRT_EXPORT namespace winrt::Windows::Storage::Streams
{
    struct IBuffer;
    struct IRandomAccessStreamWithContentType;
}
WINRT_EXPORT namespace winrt::Windows::Devices::PointOfService
{
    enum class BarcodeScannerStatus : int32_t
    {
        Online = 0,
        Off = 1,
        Offline = 2,
        OffOrOffline = 3,
        Extended = 4,
    };
    enum class BarcodeSymbologyDecodeLengthKind : int32_t
    {
        AnyLength = 0,
        Discrete = 1,
        Range = 2,
    };
    enum class CashDrawerStatusKind : int32_t
    {
        Online = 0,
        Off = 1,
        Offline = 2,
        OffOrOffline = 3,
        Extended = 4,
    };
    enum class LineDisplayCursorType : int32_t
    {
        None = 0,
        Block = 1,
        HalfBlock = 2,
        Underline = 3,
        Reverse = 4,
        Other = 5,
    };
    enum class LineDisplayDescriptorState : int32_t
    {
        Off = 0,
        On = 1,
        Blink = 2,
    };
    enum class LineDisplayHorizontalAlignment : int32_t
    {
        Left = 0,
        Center = 1,
        Right = 2,
    };
    enum class LineDisplayMarqueeFormat : int32_t
    {
        None = 0,
        Walk = 1,
        Place = 2,
    };
    enum class LineDisplayPowerStatus : int32_t
    {
        Unknown = 0,
        Online = 1,
        Off = 2,
        Offline = 3,
        OffOrOffline = 4,
    };
    enum class LineDisplayScrollDirection : int32_t
    {
        Up = 0,
        Down = 1,
        Left = 2,
        Right = 3,
    };
    enum class LineDisplayTextAttribute : int32_t
    {
        Normal = 0,
        Blink = 1,
        Reverse = 2,
        ReverseBlink = 3,
    };
    enum class LineDisplayTextAttributeGranularity : int32_t
    {
        NotSupported = 0,
        EntireDisplay = 1,
        PerCharacter = 2,
    };
    enum class LineDisplayVerticalAlignment : int32_t
    {
        Top = 0,
        Center = 1,
        Bottom = 2,
    };
    enum class MagneticStripeReaderAuthenticationLevel : int32_t
    {
        NotSupported = 0,
        Optional = 1,
        Required = 2,
    };
    enum class MagneticStripeReaderAuthenticationProtocol : int32_t
    {
        None = 0,
        ChallengeResponse = 1,
    };
    enum class MagneticStripeReaderErrorReportingType : int32_t
    {
        CardLevel = 0,
        TrackLevel = 1,
    };
    enum class MagneticStripeReaderStatus : int32_t
    {
        Unauthenticated = 0,
        Authenticated = 1,
        Extended = 2,
    };
    enum class MagneticStripeReaderTrackErrorType : int32_t
    {
        None = 0,
        StartSentinelError = 1,
        EndSentinelError = 2,
        ParityError = 3,
        LrcError = 4,
        Unknown = -1,
    };
    enum class MagneticStripeReaderTrackIds : int32_t
    {
        None = 0,
        Track1 = 1,
        Track2 = 2,
        Track3 = 4,
        Track4 = 8,
    };
    enum class PosConnectionTypes : uint32_t
    {
        Local = 0x1,
        IP = 0x2,
        Bluetooth = 0x4,
        All = 0xffffffff,
    };
    enum class PosPrinterAlignment : int32_t
    {
        Left = 0,
        Center = 1,
        Right = 2,
    };
    enum class PosPrinterBarcodeTextPosition : int32_t
    {
        None = 0,
        Above = 1,
        Below = 2,
    };
    enum class PosPrinterCartridgeSensors : uint32_t
    {
        None = 0,
        Removed = 0x1,
        Empty = 0x2,
        HeadCleaning = 0x4,
        NearEnd = 0x8,
    };
    enum class PosPrinterColorCapabilities : uint32_t
    {
        None = 0,
        Primary = 0x1,
        Custom1 = 0x2,
        Custom2 = 0x4,
        Custom3 = 0x8,
        Custom4 = 0x10,
        Custom5 = 0x20,
        Custom6 = 0x40,
        Cyan = 0x80,
        Magenta = 0x100,
        Yellow = 0x200,
        Full = 0x400,
    };
    enum class PosPrinterColorCartridge : int32_t
    {
        Unknown = 0,
        Primary = 1,
        Custom1 = 2,
        Custom2 = 3,
        Custom3 = 4,
        Custom4 = 5,
        Custom5 = 6,
        Custom6 = 7,
        Cyan = 8,
        Magenta = 9,
        Yellow = 10,
    };
    enum class PosPrinterLineDirection : int32_t
    {
        Horizontal = 0,
        Vertical = 1,
    };
    enum class PosPrinterLineStyle : int32_t
    {
        SingleSolid = 0,
        DoubleSolid = 1,
        Broken = 2,
        Chain = 3,
    };
    enum class PosPrinterMapMode : int32_t
    {
        Dots = 0,
        Twips = 1,
        English = 2,
        Metric = 3,
    };
    enum class PosPrinterMarkFeedCapabilities : uint32_t
    {
        None = 0,
        ToTakeUp = 0x1,
        ToCutter = 0x2,
        ToCurrentTopOfForm = 0x4,
        ToNextTopOfForm = 0x8,
    };
    enum class PosPrinterMarkFeedKind : int32_t
    {
        ToTakeUp = 0,
        ToCutter = 1,
        ToCurrentTopOfForm = 2,
        ToNextTopOfForm = 3,
    };
    enum class PosPrinterPrintSide : int32_t
    {
        Unknown = 0,
        Side1 = 1,
        Side2 = 2,
    };
    enum class PosPrinterRotation : int32_t
    {
        Normal = 0,
        Right90 = 1,
        Left90 = 2,
        Rotate180 = 3,
    };
    enum class PosPrinterRuledLineCapabilities : uint32_t
    {
        None = 0,
        Horizontal = 0x1,
        Vertical = 0x2,
    };
    enum class PosPrinterStatusKind : int32_t
    {
        Online = 0,
        Off = 1,
        Offline = 2,
        OffOrOffline = 3,
        Extended = 4,
    };
    enum class UnifiedPosErrorReason : int32_t
    {
        UnknownErrorReason = 0,
        NoService = 1,
        Disabled = 2,
        Illegal = 3,
        NoHardware = 4,
        Closed = 5,
        Offline = 6,
        Failure = 7,
        Timeout = 8,
        Busy = 9,
        Extended = 10,
    };
    enum class UnifiedPosErrorSeverity : int32_t
    {
        UnknownErrorSeverity = 0,
        Warning = 1,
        Recoverable = 2,
        Unrecoverable = 3,
        AssistanceRequired = 4,
        Fatal = 5,
    };
    enum class UnifiedPosHealthCheckLevel : int32_t
    {
        UnknownHealthCheckLevel = 0,
        POSInternal = 1,
        External = 2,
        Interactive = 3,
    };
    enum class UnifiedPosPowerReportingType : int32_t
    {
        UnknownPowerReportingType = 0,
        Standard = 1,
        Advanced = 2,
    };
    struct IBarcodeScanner;
    struct IBarcodeScanner2;
    struct IBarcodeScannerCapabilities;
    struct IBarcodeScannerCapabilities1;
    struct IBarcodeScannerCapabilities2;
    struct IBarcodeScannerDataReceivedEventArgs;
    struct IBarcodeScannerErrorOccurredEventArgs;
    struct IBarcodeScannerImagePreviewReceivedEventArgs;
    struct IBarcodeScannerReport;
    struct IBarcodeScannerReportFactory;
    struct IBarcodeScannerStatics;
    struct IBarcodeScannerStatics2;
    struct IBarcodeScannerStatusUpdatedEventArgs;
    struct IBarcodeSymbologiesStatics;
    struct IBarcodeSymbologiesStatics2;
    struct IBarcodeSymbologyAttributes;
    struct ICashDrawer;
    struct ICashDrawerCapabilities;
    struct ICashDrawerCloseAlarm;
    struct ICashDrawerEventSource;
    struct ICashDrawerEventSourceEventArgs;
    struct ICashDrawerStatics;
    struct ICashDrawerStatics2;
    struct ICashDrawerStatus;
    struct ICashDrawerStatusUpdatedEventArgs;
    struct IClaimedBarcodeScanner;
    struct IClaimedBarcodeScanner1;
    struct IClaimedBarcodeScanner2;
    struct IClaimedBarcodeScanner3;
    struct IClaimedBarcodeScanner4;
    struct IClaimedBarcodeScannerClosedEventArgs;
    struct IClaimedCashDrawer;
    struct IClaimedCashDrawer2;
    struct IClaimedCashDrawerClosedEventArgs;
    struct IClaimedJournalPrinter;
    struct IClaimedLineDisplay;
    struct IClaimedLineDisplay2;
    struct IClaimedLineDisplay3;
    struct IClaimedLineDisplayClosedEventArgs;
    struct IClaimedLineDisplayStatics;
    struct IClaimedMagneticStripeReader;
    struct IClaimedMagneticStripeReader2;
    struct IClaimedMagneticStripeReaderClosedEventArgs;
    struct IClaimedPosPrinter;
    struct IClaimedPosPrinter2;
    struct IClaimedPosPrinterClosedEventArgs;
    struct IClaimedReceiptPrinter;
    struct IClaimedSlipPrinter;
    struct ICommonClaimedPosPrinterStation;
    struct ICommonPosPrintStationCapabilities;
    struct ICommonReceiptSlipCapabilities;
    struct IJournalPrintJob;
    struct IJournalPrinterCapabilities;
    struct IJournalPrinterCapabilities2;
    struct ILineDisplay;
    struct ILineDisplay2;
    struct ILineDisplayAttributes;
    struct ILineDisplayCapabilities;
    struct ILineDisplayCursor;
    struct ILineDisplayCursorAttributes;
    struct ILineDisplayCustomGlyphs;
    struct ILineDisplayMarquee;
    struct ILineDisplayStatics;
    struct ILineDisplayStatics2;
    struct ILineDisplayStatisticsCategorySelector;
    struct ILineDisplayStatusUpdatedEventArgs;
    struct ILineDisplayStoredBitmap;
    struct ILineDisplayWindow;
    struct ILineDisplayWindow2;
    struct IMagneticStripeReader;
    struct IMagneticStripeReaderAamvaCardDataReceivedEventArgs;
    struct IMagneticStripeReaderBankCardDataReceivedEventArgs;
    struct IMagneticStripeReaderCapabilities;
    struct IMagneticStripeReaderCardTypesStatics;
    struct IMagneticStripeReaderEncryptionAlgorithmsStatics;
    struct IMagneticStripeReaderErrorOccurredEventArgs;
    struct IMagneticStripeReaderReport;
    struct IMagneticStripeReaderStatics;
    struct IMagneticStripeReaderStatics2;
    struct IMagneticStripeReaderStatusUpdatedEventArgs;
    struct IMagneticStripeReaderTrackData;
    struct IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs;
    struct IPosPrinter;
    struct IPosPrinter2;
    struct IPosPrinterCapabilities;
    struct IPosPrinterCharacterSetIdsStatics;
    struct IPosPrinterFontProperty;
    struct IPosPrinterJob;
    struct IPosPrinterPrintOptions;
    struct IPosPrinterReleaseDeviceRequestedEventArgs;
    struct IPosPrinterStatics;
    struct IPosPrinterStatics2;
    struct IPosPrinterStatus;
    struct IPosPrinterStatusUpdatedEventArgs;
    struct IReceiptOrSlipJob;
    struct IReceiptPrintJob;
    struct IReceiptPrintJob2;
    struct IReceiptPrinterCapabilities;
    struct IReceiptPrinterCapabilities2;
    struct ISlipPrintJob;
    struct ISlipPrinterCapabilities;
    struct ISlipPrinterCapabilities2;
    struct IUnifiedPosErrorData;
    struct IUnifiedPosErrorDataFactory;
    struct BarcodeScanner;
    struct BarcodeScannerCapabilities;
    struct BarcodeScannerDataReceivedEventArgs;
    struct BarcodeScannerErrorOccurredEventArgs;
    struct BarcodeScannerImagePreviewReceivedEventArgs;
    struct BarcodeScannerReport;
    struct BarcodeScannerStatusUpdatedEventArgs;
    struct BarcodeSymbologies;
    struct BarcodeSymbologyAttributes;
    struct CashDrawer;
    struct CashDrawerCapabilities;
    struct CashDrawerCloseAlarm;
    struct CashDrawerClosedEventArgs;
    struct CashDrawerEventSource;
    struct CashDrawerOpenedEventArgs;
    struct CashDrawerStatus;
    struct CashDrawerStatusUpdatedEventArgs;
    struct ClaimedBarcodeScanner;
    struct ClaimedBarcodeScannerClosedEventArgs;
    struct ClaimedCashDrawer;
    struct ClaimedCashDrawerClosedEventArgs;
    struct ClaimedJournalPrinter;
    struct ClaimedLineDisplay;
    struct ClaimedLineDisplayClosedEventArgs;
    struct ClaimedMagneticStripeReader;
    struct ClaimedMagneticStripeReaderClosedEventArgs;
    struct ClaimedPosPrinter;
    struct ClaimedPosPrinterClosedEventArgs;
    struct ClaimedReceiptPrinter;
    struct ClaimedSlipPrinter;
    struct JournalPrintJob;
    struct JournalPrinterCapabilities;
    struct LineDisplay;
    struct LineDisplayAttributes;
    struct LineDisplayCapabilities;
    struct LineDisplayCursor;
    struct LineDisplayCursorAttributes;
    struct LineDisplayCustomGlyphs;
    struct LineDisplayMarquee;
    struct LineDisplayStatisticsCategorySelector;
    struct LineDisplayStatusUpdatedEventArgs;
    struct LineDisplayStoredBitmap;
    struct LineDisplayWindow;
    struct MagneticStripeReader;
    struct MagneticStripeReaderAamvaCardDataReceivedEventArgs;
    struct MagneticStripeReaderBankCardDataReceivedEventArgs;
    struct MagneticStripeReaderCapabilities;
    struct MagneticStripeReaderCardTypes;
    struct MagneticStripeReaderEncryptionAlgorithms;
    struct MagneticStripeReaderErrorOccurredEventArgs;
    struct MagneticStripeReaderReport;
    struct MagneticStripeReaderStatusUpdatedEventArgs;
    struct MagneticStripeReaderTrackData;
    struct MagneticStripeReaderVendorSpecificCardDataReceivedEventArgs;
    struct PosPrinter;
    struct PosPrinterCapabilities;
    struct PosPrinterCharacterSetIds;
    struct PosPrinterFontProperty;
    struct PosPrinterPrintOptions;
    struct PosPrinterReleaseDeviceRequestedEventArgs;
    struct PosPrinterStatus;
    struct PosPrinterStatusUpdatedEventArgs;
    struct ReceiptPrintJob;
    struct ReceiptPrinterCapabilities;
    struct SlipPrintJob;
    struct SlipPrinterCapabilities;
    struct UnifiedPosErrorData;
    struct SizeUInt32;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::Devices::PointOfService::IBarcodeScanner>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IBarcodeScanner2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities1>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IBarcodeScannerDataReceivedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IBarcodeScannerErrorOccurredEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IBarcodeScannerImagePreviewReceivedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IBarcodeScannerReport>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IBarcodeScannerReportFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IBarcodeScannerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IBarcodeScannerStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IBarcodeScannerStatusUpdatedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IBarcodeSymbologyAttributes>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ICashDrawer>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ICashDrawerCapabilities>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ICashDrawerCloseAlarm>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ICashDrawerEventSource>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ICashDrawerEventSourceEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ICashDrawerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ICashDrawerStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ICashDrawerStatus>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ICashDrawerStatusUpdatedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner1>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner4>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScannerClosedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IClaimedCashDrawer>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IClaimedCashDrawer2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IClaimedCashDrawerClosedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IClaimedJournalPrinter>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IClaimedLineDisplayClosedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IClaimedLineDisplayStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReaderClosedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IClaimedPosPrinter>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IClaimedPosPrinter2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IClaimedPosPrinterClosedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IClaimedReceiptPrinter>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IClaimedSlipPrinter>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IJournalPrintJob>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IJournalPrinterCapabilities>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IJournalPrinterCapabilities2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ILineDisplay>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ILineDisplay2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ILineDisplayAttributes>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ILineDisplayCapabilities>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ILineDisplayCursor>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ILineDisplayCursorAttributes>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ILineDisplayCustomGlyphs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ILineDisplayMarquee>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ILineDisplayStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ILineDisplayStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ILineDisplayStatisticsCategorySelector>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ILineDisplayStatusUpdatedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ILineDisplayStoredBitmap>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ILineDisplayWindow>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ILineDisplayWindow2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IMagneticStripeReader>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCardTypesStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderEncryptionAlgorithmsStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderReport>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatusUpdatedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderTrackData>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IPosPrinter>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IPosPrinter2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IPosPrinterCapabilities>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IPosPrinterCharacterSetIdsStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IPosPrinterFontProperty>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IPosPrinterJob>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IPosPrinterReleaseDeviceRequestedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IPosPrinterStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IPosPrinterStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IPosPrinterStatus>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IPosPrinterStatusUpdatedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IReceiptOrSlipJob>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IReceiptPrintJob>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IReceiptPrintJob2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ISlipPrintJob>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ISlipPrinterCapabilities>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ISlipPrinterCapabilities2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IUnifiedPosErrorData>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::IUnifiedPosErrorDataFactory>{ using type = interface_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::BarcodeScanner>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::BarcodeScannerCapabilities>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::BarcodeScannerDataReceivedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::BarcodeScannerErrorOccurredEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::BarcodeScannerImagePreviewReceivedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::BarcodeScannerReport>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::BarcodeScannerStatusUpdatedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::BarcodeSymbologies>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::BarcodeSymbologyAttributes>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::CashDrawer>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::CashDrawerCapabilities>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::CashDrawerCloseAlarm>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::CashDrawerClosedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::CashDrawerEventSource>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::CashDrawerOpenedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::CashDrawerStatus>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::CashDrawerStatusUpdatedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScannerClosedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ClaimedCashDrawer>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ClaimedCashDrawerClosedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ClaimedJournalPrinter>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ClaimedLineDisplay>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ClaimedLineDisplayClosedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReaderClosedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ClaimedPosPrinter>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ClaimedPosPrinterClosedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ClaimedReceiptPrinter>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ClaimedSlipPrinter>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::JournalPrintJob>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::JournalPrinterCapabilities>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::LineDisplay>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::LineDisplayAttributes>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::LineDisplayCapabilities>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::LineDisplayCursor>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::LineDisplayCursorAttributes>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::LineDisplayCustomGlyphs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::LineDisplayMarquee>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::LineDisplayStatisticsCategorySelector>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::LineDisplayStatusUpdatedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::LineDisplayStoredBitmap>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::LineDisplayWindow>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::MagneticStripeReader>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::MagneticStripeReaderAamvaCardDataReceivedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::MagneticStripeReaderBankCardDataReceivedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::MagneticStripeReaderCapabilities>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::MagneticStripeReaderCardTypes>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::MagneticStripeReaderEncryptionAlgorithms>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::MagneticStripeReaderErrorOccurredEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::MagneticStripeReaderReport>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::MagneticStripeReaderStatusUpdatedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackData>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::MagneticStripeReaderVendorSpecificCardDataReceivedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::PosPrinter>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::PosPrinterCapabilities>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::PosPrinterCharacterSetIds>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::PosPrinterFontProperty>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::PosPrinterPrintOptions>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::PosPrinterReleaseDeviceRequestedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::PosPrinterStatus>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::PosPrinterStatusUpdatedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ReceiptPrintJob>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::ReceiptPrinterCapabilities>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::SlipPrintJob>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::SlipPrinterCapabilities>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::UnifiedPosErrorData>{ using type = class_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::BarcodeScannerStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::BarcodeSymbologyDecodeLengthKind>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::CashDrawerStatusKind>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::LineDisplayCursorType>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::LineDisplayDescriptorState>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::LineDisplayHorizontalAlignment>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::LineDisplayMarqueeFormat>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::LineDisplayPowerStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::LineDisplayScrollDirection>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::LineDisplayTextAttribute>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::LineDisplayTextAttributeGranularity>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::LineDisplayVerticalAlignment>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationLevel>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationProtocol>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::MagneticStripeReaderErrorReportingType>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::MagneticStripeReaderStatus>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackIds>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::PosConnectionTypes>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::PosPrinterAlignment>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::PosPrinterBarcodeTextPosition>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::PosPrinterCartridgeSensors>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::PosPrinterColorCapabilities>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::PosPrinterColorCartridge>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::PosPrinterLineDirection>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::PosPrinterLineStyle>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::PosPrinterMapMode>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::PosPrinterMarkFeedCapabilities>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::PosPrinterMarkFeedKind>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::PosPrinterPrintSide>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::PosPrinterRotation>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::PosPrinterRuledLineCapabilities>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::PosPrinterStatusKind>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::UnifiedPosErrorReason>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::UnifiedPosErrorSeverity>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::UnifiedPosPowerReportingType>{ using type = enum_category; };
    template <> struct category<winrt::Windows::Devices::PointOfService::SizeUInt32>{ using type = struct_category<uint32_t, uint32_t>; };
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::BarcodeScanner> = L"Windows.Devices.PointOfService.BarcodeScanner";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::BarcodeScannerCapabilities> = L"Windows.Devices.PointOfService.BarcodeScannerCapabilities";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::BarcodeScannerDataReceivedEventArgs> = L"Windows.Devices.PointOfService.BarcodeScannerDataReceivedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::BarcodeScannerErrorOccurredEventArgs> = L"Windows.Devices.PointOfService.BarcodeScannerErrorOccurredEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::BarcodeScannerImagePreviewReceivedEventArgs> = L"Windows.Devices.PointOfService.BarcodeScannerImagePreviewReceivedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::BarcodeScannerReport> = L"Windows.Devices.PointOfService.BarcodeScannerReport";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::BarcodeScannerStatusUpdatedEventArgs> = L"Windows.Devices.PointOfService.BarcodeScannerStatusUpdatedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::BarcodeSymbologies> = L"Windows.Devices.PointOfService.BarcodeSymbologies";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::BarcodeSymbologyAttributes> = L"Windows.Devices.PointOfService.BarcodeSymbologyAttributes";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::CashDrawer> = L"Windows.Devices.PointOfService.CashDrawer";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::CashDrawerCapabilities> = L"Windows.Devices.PointOfService.CashDrawerCapabilities";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::CashDrawerCloseAlarm> = L"Windows.Devices.PointOfService.CashDrawerCloseAlarm";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::CashDrawerClosedEventArgs> = L"Windows.Devices.PointOfService.CashDrawerClosedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::CashDrawerEventSource> = L"Windows.Devices.PointOfService.CashDrawerEventSource";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::CashDrawerOpenedEventArgs> = L"Windows.Devices.PointOfService.CashDrawerOpenedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::CashDrawerStatus> = L"Windows.Devices.PointOfService.CashDrawerStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::CashDrawerStatusUpdatedEventArgs> = L"Windows.Devices.PointOfService.CashDrawerStatusUpdatedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner> = L"Windows.Devices.PointOfService.ClaimedBarcodeScanner";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScannerClosedEventArgs> = L"Windows.Devices.PointOfService.ClaimedBarcodeScannerClosedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ClaimedCashDrawer> = L"Windows.Devices.PointOfService.ClaimedCashDrawer";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ClaimedCashDrawerClosedEventArgs> = L"Windows.Devices.PointOfService.ClaimedCashDrawerClosedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ClaimedJournalPrinter> = L"Windows.Devices.PointOfService.ClaimedJournalPrinter";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ClaimedLineDisplay> = L"Windows.Devices.PointOfService.ClaimedLineDisplay";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ClaimedLineDisplayClosedEventArgs> = L"Windows.Devices.PointOfService.ClaimedLineDisplayClosedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader> = L"Windows.Devices.PointOfService.ClaimedMagneticStripeReader";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReaderClosedEventArgs> = L"Windows.Devices.PointOfService.ClaimedMagneticStripeReaderClosedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ClaimedPosPrinter> = L"Windows.Devices.PointOfService.ClaimedPosPrinter";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ClaimedPosPrinterClosedEventArgs> = L"Windows.Devices.PointOfService.ClaimedPosPrinterClosedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ClaimedReceiptPrinter> = L"Windows.Devices.PointOfService.ClaimedReceiptPrinter";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ClaimedSlipPrinter> = L"Windows.Devices.PointOfService.ClaimedSlipPrinter";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::JournalPrintJob> = L"Windows.Devices.PointOfService.JournalPrintJob";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::JournalPrinterCapabilities> = L"Windows.Devices.PointOfService.JournalPrinterCapabilities";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::LineDisplay> = L"Windows.Devices.PointOfService.LineDisplay";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::LineDisplayAttributes> = L"Windows.Devices.PointOfService.LineDisplayAttributes";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::LineDisplayCapabilities> = L"Windows.Devices.PointOfService.LineDisplayCapabilities";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::LineDisplayCursor> = L"Windows.Devices.PointOfService.LineDisplayCursor";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::LineDisplayCursorAttributes> = L"Windows.Devices.PointOfService.LineDisplayCursorAttributes";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::LineDisplayCustomGlyphs> = L"Windows.Devices.PointOfService.LineDisplayCustomGlyphs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::LineDisplayMarquee> = L"Windows.Devices.PointOfService.LineDisplayMarquee";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::LineDisplayStatisticsCategorySelector> = L"Windows.Devices.PointOfService.LineDisplayStatisticsCategorySelector";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::LineDisplayStatusUpdatedEventArgs> = L"Windows.Devices.PointOfService.LineDisplayStatusUpdatedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::LineDisplayStoredBitmap> = L"Windows.Devices.PointOfService.LineDisplayStoredBitmap";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::LineDisplayWindow> = L"Windows.Devices.PointOfService.LineDisplayWindow";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::MagneticStripeReader> = L"Windows.Devices.PointOfService.MagneticStripeReader";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::MagneticStripeReaderAamvaCardDataReceivedEventArgs> = L"Windows.Devices.PointOfService.MagneticStripeReaderAamvaCardDataReceivedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::MagneticStripeReaderBankCardDataReceivedEventArgs> = L"Windows.Devices.PointOfService.MagneticStripeReaderBankCardDataReceivedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::MagneticStripeReaderCapabilities> = L"Windows.Devices.PointOfService.MagneticStripeReaderCapabilities";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::MagneticStripeReaderCardTypes> = L"Windows.Devices.PointOfService.MagneticStripeReaderCardTypes";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::MagneticStripeReaderEncryptionAlgorithms> = L"Windows.Devices.PointOfService.MagneticStripeReaderEncryptionAlgorithms";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::MagneticStripeReaderErrorOccurredEventArgs> = L"Windows.Devices.PointOfService.MagneticStripeReaderErrorOccurredEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::MagneticStripeReaderReport> = L"Windows.Devices.PointOfService.MagneticStripeReaderReport";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::MagneticStripeReaderStatusUpdatedEventArgs> = L"Windows.Devices.PointOfService.MagneticStripeReaderStatusUpdatedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackData> = L"Windows.Devices.PointOfService.MagneticStripeReaderTrackData";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::MagneticStripeReaderVendorSpecificCardDataReceivedEventArgs> = L"Windows.Devices.PointOfService.MagneticStripeReaderVendorSpecificCardDataReceivedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::PosPrinter> = L"Windows.Devices.PointOfService.PosPrinter";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::PosPrinterCapabilities> = L"Windows.Devices.PointOfService.PosPrinterCapabilities";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::PosPrinterCharacterSetIds> = L"Windows.Devices.PointOfService.PosPrinterCharacterSetIds";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::PosPrinterFontProperty> = L"Windows.Devices.PointOfService.PosPrinterFontProperty";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::PosPrinterPrintOptions> = L"Windows.Devices.PointOfService.PosPrinterPrintOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::PosPrinterReleaseDeviceRequestedEventArgs> = L"Windows.Devices.PointOfService.PosPrinterReleaseDeviceRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::PosPrinterStatus> = L"Windows.Devices.PointOfService.PosPrinterStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::PosPrinterStatusUpdatedEventArgs> = L"Windows.Devices.PointOfService.PosPrinterStatusUpdatedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ReceiptPrintJob> = L"Windows.Devices.PointOfService.ReceiptPrintJob";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ReceiptPrinterCapabilities> = L"Windows.Devices.PointOfService.ReceiptPrinterCapabilities";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::SlipPrintJob> = L"Windows.Devices.PointOfService.SlipPrintJob";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::SlipPrinterCapabilities> = L"Windows.Devices.PointOfService.SlipPrinterCapabilities";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::UnifiedPosErrorData> = L"Windows.Devices.PointOfService.UnifiedPosErrorData";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::BarcodeScannerStatus> = L"Windows.Devices.PointOfService.BarcodeScannerStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::BarcodeSymbologyDecodeLengthKind> = L"Windows.Devices.PointOfService.BarcodeSymbologyDecodeLengthKind";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::CashDrawerStatusKind> = L"Windows.Devices.PointOfService.CashDrawerStatusKind";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::LineDisplayCursorType> = L"Windows.Devices.PointOfService.LineDisplayCursorType";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::LineDisplayDescriptorState> = L"Windows.Devices.PointOfService.LineDisplayDescriptorState";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::LineDisplayHorizontalAlignment> = L"Windows.Devices.PointOfService.LineDisplayHorizontalAlignment";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::LineDisplayMarqueeFormat> = L"Windows.Devices.PointOfService.LineDisplayMarqueeFormat";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::LineDisplayPowerStatus> = L"Windows.Devices.PointOfService.LineDisplayPowerStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::LineDisplayScrollDirection> = L"Windows.Devices.PointOfService.LineDisplayScrollDirection";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::LineDisplayTextAttribute> = L"Windows.Devices.PointOfService.LineDisplayTextAttribute";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::LineDisplayTextAttributeGranularity> = L"Windows.Devices.PointOfService.LineDisplayTextAttributeGranularity";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::LineDisplayVerticalAlignment> = L"Windows.Devices.PointOfService.LineDisplayVerticalAlignment";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationLevel> = L"Windows.Devices.PointOfService.MagneticStripeReaderAuthenticationLevel";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationProtocol> = L"Windows.Devices.PointOfService.MagneticStripeReaderAuthenticationProtocol";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::MagneticStripeReaderErrorReportingType> = L"Windows.Devices.PointOfService.MagneticStripeReaderErrorReportingType";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::MagneticStripeReaderStatus> = L"Windows.Devices.PointOfService.MagneticStripeReaderStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType> = L"Windows.Devices.PointOfService.MagneticStripeReaderTrackErrorType";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackIds> = L"Windows.Devices.PointOfService.MagneticStripeReaderTrackIds";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::PosConnectionTypes> = L"Windows.Devices.PointOfService.PosConnectionTypes";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::PosPrinterAlignment> = L"Windows.Devices.PointOfService.PosPrinterAlignment";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::PosPrinterBarcodeTextPosition> = L"Windows.Devices.PointOfService.PosPrinterBarcodeTextPosition";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::PosPrinterCartridgeSensors> = L"Windows.Devices.PointOfService.PosPrinterCartridgeSensors";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::PosPrinterColorCapabilities> = L"Windows.Devices.PointOfService.PosPrinterColorCapabilities";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::PosPrinterColorCartridge> = L"Windows.Devices.PointOfService.PosPrinterColorCartridge";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::PosPrinterLineDirection> = L"Windows.Devices.PointOfService.PosPrinterLineDirection";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::PosPrinterLineStyle> = L"Windows.Devices.PointOfService.PosPrinterLineStyle";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::PosPrinterMapMode> = L"Windows.Devices.PointOfService.PosPrinterMapMode";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::PosPrinterMarkFeedCapabilities> = L"Windows.Devices.PointOfService.PosPrinterMarkFeedCapabilities";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::PosPrinterMarkFeedKind> = L"Windows.Devices.PointOfService.PosPrinterMarkFeedKind";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::PosPrinterPrintSide> = L"Windows.Devices.PointOfService.PosPrinterPrintSide";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::PosPrinterRotation> = L"Windows.Devices.PointOfService.PosPrinterRotation";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::PosPrinterRuledLineCapabilities> = L"Windows.Devices.PointOfService.PosPrinterRuledLineCapabilities";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::PosPrinterStatusKind> = L"Windows.Devices.PointOfService.PosPrinterStatusKind";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::UnifiedPosErrorReason> = L"Windows.Devices.PointOfService.UnifiedPosErrorReason";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::UnifiedPosErrorSeverity> = L"Windows.Devices.PointOfService.UnifiedPosErrorSeverity";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel> = L"Windows.Devices.PointOfService.UnifiedPosHealthCheckLevel";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::UnifiedPosPowerReportingType> = L"Windows.Devices.PointOfService.UnifiedPosPowerReportingType";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::SizeUInt32> = L"Windows.Devices.PointOfService.SizeUInt32";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IBarcodeScanner> = L"Windows.Devices.PointOfService.IBarcodeScanner";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IBarcodeScanner2> = L"Windows.Devices.PointOfService.IBarcodeScanner2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities> = L"Windows.Devices.PointOfService.IBarcodeScannerCapabilities";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities1> = L"Windows.Devices.PointOfService.IBarcodeScannerCapabilities1";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities2> = L"Windows.Devices.PointOfService.IBarcodeScannerCapabilities2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IBarcodeScannerDataReceivedEventArgs> = L"Windows.Devices.PointOfService.IBarcodeScannerDataReceivedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IBarcodeScannerErrorOccurredEventArgs> = L"Windows.Devices.PointOfService.IBarcodeScannerErrorOccurredEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IBarcodeScannerImagePreviewReceivedEventArgs> = L"Windows.Devices.PointOfService.IBarcodeScannerImagePreviewReceivedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IBarcodeScannerReport> = L"Windows.Devices.PointOfService.IBarcodeScannerReport";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IBarcodeScannerReportFactory> = L"Windows.Devices.PointOfService.IBarcodeScannerReportFactory";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IBarcodeScannerStatics> = L"Windows.Devices.PointOfService.IBarcodeScannerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IBarcodeScannerStatics2> = L"Windows.Devices.PointOfService.IBarcodeScannerStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IBarcodeScannerStatusUpdatedEventArgs> = L"Windows.Devices.PointOfService.IBarcodeScannerStatusUpdatedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics> = L"Windows.Devices.PointOfService.IBarcodeSymbologiesStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics2> = L"Windows.Devices.PointOfService.IBarcodeSymbologiesStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IBarcodeSymbologyAttributes> = L"Windows.Devices.PointOfService.IBarcodeSymbologyAttributes";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ICashDrawer> = L"Windows.Devices.PointOfService.ICashDrawer";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ICashDrawerCapabilities> = L"Windows.Devices.PointOfService.ICashDrawerCapabilities";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ICashDrawerCloseAlarm> = L"Windows.Devices.PointOfService.ICashDrawerCloseAlarm";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ICashDrawerEventSource> = L"Windows.Devices.PointOfService.ICashDrawerEventSource";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ICashDrawerEventSourceEventArgs> = L"Windows.Devices.PointOfService.ICashDrawerEventSourceEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ICashDrawerStatics> = L"Windows.Devices.PointOfService.ICashDrawerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ICashDrawerStatics2> = L"Windows.Devices.PointOfService.ICashDrawerStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ICashDrawerStatus> = L"Windows.Devices.PointOfService.ICashDrawerStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ICashDrawerStatusUpdatedEventArgs> = L"Windows.Devices.PointOfService.ICashDrawerStatusUpdatedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner> = L"Windows.Devices.PointOfService.IClaimedBarcodeScanner";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner1> = L"Windows.Devices.PointOfService.IClaimedBarcodeScanner1";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner2> = L"Windows.Devices.PointOfService.IClaimedBarcodeScanner2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner3> = L"Windows.Devices.PointOfService.IClaimedBarcodeScanner3";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner4> = L"Windows.Devices.PointOfService.IClaimedBarcodeScanner4";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScannerClosedEventArgs> = L"Windows.Devices.PointOfService.IClaimedBarcodeScannerClosedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IClaimedCashDrawer> = L"Windows.Devices.PointOfService.IClaimedCashDrawer";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IClaimedCashDrawer2> = L"Windows.Devices.PointOfService.IClaimedCashDrawer2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IClaimedCashDrawerClosedEventArgs> = L"Windows.Devices.PointOfService.IClaimedCashDrawerClosedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IClaimedJournalPrinter> = L"Windows.Devices.PointOfService.IClaimedJournalPrinter";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay> = L"Windows.Devices.PointOfService.IClaimedLineDisplay";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay2> = L"Windows.Devices.PointOfService.IClaimedLineDisplay2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay3> = L"Windows.Devices.PointOfService.IClaimedLineDisplay3";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IClaimedLineDisplayClosedEventArgs> = L"Windows.Devices.PointOfService.IClaimedLineDisplayClosedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IClaimedLineDisplayStatics> = L"Windows.Devices.PointOfService.IClaimedLineDisplayStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader> = L"Windows.Devices.PointOfService.IClaimedMagneticStripeReader";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader2> = L"Windows.Devices.PointOfService.IClaimedMagneticStripeReader2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReaderClosedEventArgs> = L"Windows.Devices.PointOfService.IClaimedMagneticStripeReaderClosedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IClaimedPosPrinter> = L"Windows.Devices.PointOfService.IClaimedPosPrinter";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IClaimedPosPrinter2> = L"Windows.Devices.PointOfService.IClaimedPosPrinter2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IClaimedPosPrinterClosedEventArgs> = L"Windows.Devices.PointOfService.IClaimedPosPrinterClosedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IClaimedReceiptPrinter> = L"Windows.Devices.PointOfService.IClaimedReceiptPrinter";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IClaimedSlipPrinter> = L"Windows.Devices.PointOfService.IClaimedSlipPrinter";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation> = L"Windows.Devices.PointOfService.ICommonClaimedPosPrinterStation";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities> = L"Windows.Devices.PointOfService.ICommonPosPrintStationCapabilities";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities> = L"Windows.Devices.PointOfService.ICommonReceiptSlipCapabilities";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IJournalPrintJob> = L"Windows.Devices.PointOfService.IJournalPrintJob";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IJournalPrinterCapabilities> = L"Windows.Devices.PointOfService.IJournalPrinterCapabilities";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IJournalPrinterCapabilities2> = L"Windows.Devices.PointOfService.IJournalPrinterCapabilities2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ILineDisplay> = L"Windows.Devices.PointOfService.ILineDisplay";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ILineDisplay2> = L"Windows.Devices.PointOfService.ILineDisplay2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ILineDisplayAttributes> = L"Windows.Devices.PointOfService.ILineDisplayAttributes";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ILineDisplayCapabilities> = L"Windows.Devices.PointOfService.ILineDisplayCapabilities";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ILineDisplayCursor> = L"Windows.Devices.PointOfService.ILineDisplayCursor";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ILineDisplayCursorAttributes> = L"Windows.Devices.PointOfService.ILineDisplayCursorAttributes";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ILineDisplayCustomGlyphs> = L"Windows.Devices.PointOfService.ILineDisplayCustomGlyphs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ILineDisplayMarquee> = L"Windows.Devices.PointOfService.ILineDisplayMarquee";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ILineDisplayStatics> = L"Windows.Devices.PointOfService.ILineDisplayStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ILineDisplayStatics2> = L"Windows.Devices.PointOfService.ILineDisplayStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ILineDisplayStatisticsCategorySelector> = L"Windows.Devices.PointOfService.ILineDisplayStatisticsCategorySelector";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ILineDisplayStatusUpdatedEventArgs> = L"Windows.Devices.PointOfService.ILineDisplayStatusUpdatedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ILineDisplayStoredBitmap> = L"Windows.Devices.PointOfService.ILineDisplayStoredBitmap";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ILineDisplayWindow> = L"Windows.Devices.PointOfService.ILineDisplayWindow";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ILineDisplayWindow2> = L"Windows.Devices.PointOfService.ILineDisplayWindow2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IMagneticStripeReader> = L"Windows.Devices.PointOfService.IMagneticStripeReader";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs> = L"Windows.Devices.PointOfService.IMagneticStripeReaderAamvaCardDataReceivedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs> = L"Windows.Devices.PointOfService.IMagneticStripeReaderBankCardDataReceivedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities> = L"Windows.Devices.PointOfService.IMagneticStripeReaderCapabilities";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCardTypesStatics> = L"Windows.Devices.PointOfService.IMagneticStripeReaderCardTypesStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderEncryptionAlgorithmsStatics> = L"Windows.Devices.PointOfService.IMagneticStripeReaderEncryptionAlgorithmsStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs> = L"Windows.Devices.PointOfService.IMagneticStripeReaderErrorOccurredEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderReport> = L"Windows.Devices.PointOfService.IMagneticStripeReaderReport";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatics> = L"Windows.Devices.PointOfService.IMagneticStripeReaderStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatics2> = L"Windows.Devices.PointOfService.IMagneticStripeReaderStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatusUpdatedEventArgs> = L"Windows.Devices.PointOfService.IMagneticStripeReaderStatusUpdatedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderTrackData> = L"Windows.Devices.PointOfService.IMagneticStripeReaderTrackData";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs> = L"Windows.Devices.PointOfService.IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IPosPrinter> = L"Windows.Devices.PointOfService.IPosPrinter";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IPosPrinter2> = L"Windows.Devices.PointOfService.IPosPrinter2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IPosPrinterCapabilities> = L"Windows.Devices.PointOfService.IPosPrinterCapabilities";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IPosPrinterCharacterSetIdsStatics> = L"Windows.Devices.PointOfService.IPosPrinterCharacterSetIdsStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IPosPrinterFontProperty> = L"Windows.Devices.PointOfService.IPosPrinterFontProperty";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IPosPrinterJob> = L"Windows.Devices.PointOfService.IPosPrinterJob";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions> = L"Windows.Devices.PointOfService.IPosPrinterPrintOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IPosPrinterReleaseDeviceRequestedEventArgs> = L"Windows.Devices.PointOfService.IPosPrinterReleaseDeviceRequestedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IPosPrinterStatics> = L"Windows.Devices.PointOfService.IPosPrinterStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IPosPrinterStatics2> = L"Windows.Devices.PointOfService.IPosPrinterStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IPosPrinterStatus> = L"Windows.Devices.PointOfService.IPosPrinterStatus";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IPosPrinterStatusUpdatedEventArgs> = L"Windows.Devices.PointOfService.IPosPrinterStatusUpdatedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IReceiptOrSlipJob> = L"Windows.Devices.PointOfService.IReceiptOrSlipJob";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IReceiptPrintJob> = L"Windows.Devices.PointOfService.IReceiptPrintJob";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IReceiptPrintJob2> = L"Windows.Devices.PointOfService.IReceiptPrintJob2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities> = L"Windows.Devices.PointOfService.IReceiptPrinterCapabilities";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities2> = L"Windows.Devices.PointOfService.IReceiptPrinterCapabilities2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ISlipPrintJob> = L"Windows.Devices.PointOfService.ISlipPrintJob";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ISlipPrinterCapabilities> = L"Windows.Devices.PointOfService.ISlipPrinterCapabilities";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::ISlipPrinterCapabilities2> = L"Windows.Devices.PointOfService.ISlipPrinterCapabilities2";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IUnifiedPosErrorData> = L"Windows.Devices.PointOfService.IUnifiedPosErrorData";
    template <> inline constexpr auto& name_v<winrt::Windows::Devices::PointOfService::IUnifiedPosErrorDataFactory> = L"Windows.Devices.PointOfService.IUnifiedPosErrorDataFactory";
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IBarcodeScanner>{ 0xBEA33E06,0xB264,0x4F03,{ 0xA9,0xC1,0x45,0xB2,0x0F,0x01,0x13,0x4F } }; // BEA33E06-B264-4F03-A9C1-45B20F01134F
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IBarcodeScanner2>{ 0x89215167,0x8CEE,0x436D,{ 0x89,0xAB,0x8D,0xFB,0x43,0xBB,0x42,0x86 } }; // 89215167-8CEE-436D-89AB-8DFB43BB4286
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities>{ 0xC60691E4,0xF2C8,0x4420,{ 0xA3,0x07,0xB1,0x2E,0xF6,0x62,0x28,0x57 } }; // C60691E4-F2C8-4420-A307-B12EF6622857
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities1>{ 0x8E5AB3E9,0x0E2C,0x472F,{ 0xA1,0xCC,0xEE,0x80,0x54,0xB6,0xA6,0x84 } }; // 8E5AB3E9-0E2C-472F-A1CC-EE8054B6A684
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities2>{ 0xF211CFEC,0xE1A1,0x4EA8,{ 0x9A,0xBC,0x92,0xB1,0x59,0x62,0x70,0xAB } }; // F211CFEC-E1A1-4EA8-9ABC-92B1596270AB
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IBarcodeScannerDataReceivedEventArgs>{ 0x4234A7E2,0xED97,0x467D,{ 0xAD,0x2B,0x01,0xE4,0x43,0x13,0xA9,0x29 } }; // 4234A7E2-ED97-467D-AD2B-01E44313A929
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IBarcodeScannerErrorOccurredEventArgs>{ 0x2CD2602F,0xCF3A,0x4002,{ 0xA7,0x5A,0xC5,0xEC,0x46,0x8F,0x0A,0x20 } }; // 2CD2602F-CF3A-4002-A75A-C5EC468F0A20
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IBarcodeScannerImagePreviewReceivedEventArgs>{ 0xF3B7DE85,0x6E8B,0x434E,{ 0x9F,0x58,0x06,0xEF,0x26,0xBC,0x4B,0xAF } }; // F3B7DE85-6E8B-434E-9F58-06EF26BC4BAF
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IBarcodeScannerReport>{ 0x5CE4D8B0,0xA489,0x4B96,{ 0x86,0xC4,0xF0,0xBF,0x8A,0x37,0x75,0x3D } }; // 5CE4D8B0-A489-4B96-86C4-F0BF8A37753D
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IBarcodeScannerReportFactory>{ 0xA2547326,0x2013,0x457C,{ 0x89,0x63,0x49,0xC1,0x5D,0xCA,0x78,0xCE } }; // A2547326-2013-457C-8963-49C15DCA78CE
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IBarcodeScannerStatics>{ 0x5D115F6F,0xDA49,0x41E8,{ 0x8C,0x8C,0xF0,0xCB,0x62,0xA9,0xC4,0xFC } }; // 5D115F6F-DA49-41E8-8C8C-F0CB62A9C4FC
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IBarcodeScannerStatics2>{ 0xB8652473,0xA36F,0x4007,{ 0xB1,0xD0,0x27,0x9E,0xBE,0x92,0xA6,0x56 } }; // B8652473-A36F-4007-B1D0-279EBE92A656
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IBarcodeScannerStatusUpdatedEventArgs>{ 0x355D8586,0x9C43,0x462B,{ 0xA9,0x1A,0x81,0x6D,0xC9,0x7F,0x45,0x2C } }; // 355D8586-9C43-462B-A91A-816DC97F452C
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>{ 0xCA8549BB,0x06D2,0x43F4,{ 0xA4,0x4B,0xC6,0x20,0x67,0x9F,0xD8,0xD0 } }; // CA8549BB-06D2-43F4-A44B-C620679FD8D0
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics2>{ 0x8B7518F4,0x99D0,0x40BF,{ 0x94,0x24,0xB9,0x1D,0x6D,0xD4,0xC6,0xE0 } }; // 8B7518F4-99D0-40BF-9424-B91D6DD4C6E0
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IBarcodeSymbologyAttributes>{ 0x66413A78,0xAB7A,0x4ADA,{ 0x8E,0xCE,0x93,0x60,0x14,0xB2,0xEA,0xD7 } }; // 66413A78-AB7A-4ADA-8ECE-936014B2EAD7
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ICashDrawer>{ 0x9F88F5C8,0xDE54,0x4AEE,{ 0xA8,0x90,0x92,0x0B,0xCB,0xFE,0x30,0xFC } }; // 9F88F5C8-DE54-4AEE-A890-920BCBFE30FC
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ICashDrawerCapabilities>{ 0x0BC6DE0B,0xE8E7,0x4B1F,{ 0xB1,0xD1,0x3E,0x50,0x1A,0xD0,0x82,0x47 } }; // 0BC6DE0B-E8E7-4B1F-B1D1-3E501AD08247
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ICashDrawerCloseAlarm>{ 0x6BF88CC7,0x6F63,0x430E,{ 0xAB,0x3B,0x95,0xD7,0x5F,0xFB,0xE8,0x7F } }; // 6BF88CC7-6F63-430E-AB3B-95D75FFBE87F
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ICashDrawerEventSource>{ 0xE006E46C,0xF2F9,0x442F,{ 0x8D,0xD6,0x06,0xC1,0x0A,0x42,0x27,0xBA } }; // E006E46C-F2F9-442F-8DD6-06C10A4227BA
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ICashDrawerEventSourceEventArgs>{ 0x69CB3BC1,0x147F,0x421C,{ 0x9C,0x23,0x09,0x01,0x23,0xBB,0x78,0x6C } }; // 69CB3BC1-147F-421C-9C23-090123BB786C
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ICashDrawerStatics>{ 0xDFA0955A,0xD437,0x4FFF,{ 0xB5,0x47,0xDD,0xA9,0x69,0xA4,0xF8,0x83 } }; // DFA0955A-D437-4FFF-B547-DDA969A4F883
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ICashDrawerStatics2>{ 0x3E818121,0x8C42,0x40E8,{ 0x9C,0x0E,0x40,0x29,0x70,0x48,0x10,0x4C } }; // 3E818121-8C42-40E8-9C0E-40297048104C
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ICashDrawerStatus>{ 0x6BBD78BF,0xDCA1,0x4E06,{ 0x99,0xEB,0x5A,0xF6,0xA5,0xAE,0xC1,0x08 } }; // 6BBD78BF-DCA1-4E06-99EB-5AF6A5AEC108
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ICashDrawerStatusUpdatedEventArgs>{ 0x30AAE98A,0x0D70,0x459C,{ 0x95,0x53,0x87,0xE1,0x24,0xC5,0x24,0x88 } }; // 30AAE98A-0D70-459C-9553-87E124C52488
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner>{ 0x4A63B49C,0x8FA4,0x4332,{ 0xBB,0x26,0x94,0x5D,0x11,0xD8,0x1E,0x0F } }; // 4A63B49C-8FA4-4332-BB26-945D11D81E0F
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner1>{ 0xF61AAD0C,0x8551,0x42B4,{ 0x99,0x8C,0x97,0x0C,0x20,0x21,0x0A,0x22 } }; // F61AAD0C-8551-42B4-998C-970C20210A22
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner2>{ 0xE3B59E8C,0x2D8B,0x4F70,{ 0x8A,0xF3,0x34,0x48,0xBE,0xDD,0x5F,0xE2 } }; // E3B59E8C-2D8B-4F70-8AF3-3448BEDD5FE2
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner3>{ 0xE6CEB430,0x712E,0x45FC,{ 0x8B,0x86,0xCD,0x55,0xF5,0xAE,0xF7,0x9D } }; // E6CEB430-712E-45FC-8B86-CD55F5AEF79D
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner4>{ 0x5D501F97,0x376A,0x41A8,{ 0xA2,0x30,0x2F,0x37,0xC1,0x94,0x9D,0xDE } }; // 5D501F97-376A-41A8-A230-2F37C1949DDE
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScannerClosedEventArgs>{ 0xCF7D5489,0xA22C,0x4C65,{ 0xA9,0x01,0x88,0xD7,0x7D,0x83,0x39,0x54 } }; // CF7D5489-A22C-4C65-A901-88D77D833954
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IClaimedCashDrawer>{ 0xCA3F99AF,0xABB8,0x42C1,{ 0x8A,0x84,0x5C,0x66,0x51,0x2F,0x5A,0x75 } }; // CA3F99AF-ABB8-42C1-8A84-5C66512F5A75
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IClaimedCashDrawer2>{ 0x9CBAB5A2,0xDE42,0x4D5B,{ 0xB0,0xC1,0x9B,0x57,0xA2,0xBA,0x89,0xC3 } }; // 9CBAB5A2-DE42-4D5B-B0C1-9B57A2BA89C3
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IClaimedCashDrawerClosedEventArgs>{ 0xCC573F33,0x3F34,0x4C5C,{ 0xBA,0xAE,0xDE,0xAD,0xF1,0x6C,0xD7,0xFA } }; // CC573F33-3F34-4C5C-BAAE-DEADF16CD7FA
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IClaimedJournalPrinter>{ 0x67EA0630,0x517D,0x487F,{ 0x9F,0xDF,0xD2,0xE0,0xA0,0xA2,0x64,0xA5 } }; // 67EA0630-517D-487F-9FDF-D2E0A0A264A5
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay>{ 0x120AC970,0x9A75,0x4ACF,{ 0xAA,0xE7,0x09,0x97,0x2B,0xCF,0x87,0x94 } }; // 120AC970-9A75-4ACF-AAE7-09972BCF8794
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay2>{ 0xA31C75ED,0x41F5,0x4E76,{ 0xA0,0x74,0x79,0x5E,0x47,0xA4,0x6E,0x97 } }; // A31C75ED-41F5-4E76-A074-795E47A46E97
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay3>{ 0x642ECD92,0xE9D4,0x4ECC,{ 0xAF,0x75,0x32,0x9C,0x27,0x4C,0xD1,0x8F } }; // 642ECD92-E9D4-4ECC-AF75-329C274CD18F
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IClaimedLineDisplayClosedEventArgs>{ 0xF915F364,0xD3D5,0x4F10,{ 0xB5,0x11,0x90,0x93,0x9E,0xDF,0xAC,0xD8 } }; // F915F364-D3D5-4F10-B511-90939EDFACD8
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IClaimedLineDisplayStatics>{ 0x78CA98FB,0x8B6B,0x4973,{ 0x86,0xF0,0x3E,0x57,0x0C,0x35,0x18,0x25 } }; // 78CA98FB-8B6B-4973-86F0-3E570C351825
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader>{ 0x475CA8F3,0x9417,0x48BC,{ 0xB9,0xD7,0x41,0x63,0xA7,0x84,0x4C,0x02 } }; // 475CA8F3-9417-48BC-B9D7-4163A7844C02
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader2>{ 0x236FAFDF,0xE2DC,0x4D7D,{ 0x9C,0x78,0x06,0x0D,0xF2,0xBF,0x29,0x28 } }; // 236FAFDF-E2DC-4D7D-9C78-060DF2BF2928
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReaderClosedEventArgs>{ 0x14ADA93A,0xADCD,0x4C80,{ 0xAC,0xDA,0xC3,0xEA,0xED,0x26,0x47,0xE1 } }; // 14ADA93A-ADCD-4C80-ACDA-C3EAED2647E1
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IClaimedPosPrinter>{ 0x6D64CE0C,0xE03E,0x4B14,{ 0xA3,0x8E,0xC2,0x8C,0x34,0xB8,0x63,0x53 } }; // 6D64CE0C-E03E-4B14-A38E-C28C34B86353
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IClaimedPosPrinter2>{ 0x5BF7A3D5,0x5198,0x437A,{ 0x82,0xDF,0x58,0x99,0x93,0xFA,0x77,0xE1 } }; // 5BF7A3D5-5198-437A-82DF-589993FA77E1
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IClaimedPosPrinterClosedEventArgs>{ 0xE2B7A27B,0x4D40,0x471D,{ 0x92,0xED,0x63,0x37,0x5B,0x18,0xC7,0x88 } }; // E2B7A27B-4D40-471D-92ED-63375B18C788
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IClaimedReceiptPrinter>{ 0x9AD27A74,0xDD61,0x4EE2,{ 0x98,0x37,0x5B,0x5D,0x72,0xD5,0x38,0xB9 } }; // 9AD27A74-DD61-4EE2-9837-5B5D72D538B9
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IClaimedSlipPrinter>{ 0xBD5DEFF2,0xAF90,0x4E8A,{ 0xB7,0x7B,0xE3,0xAE,0x9C,0xA6,0x3A,0x7F } }; // BD5DEFF2-AF90-4E8A-B77B-E3AE9CA63A7F
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation>{ 0xB7EB66A8,0xFE8A,0x4CFB,{ 0x8B,0x42,0xE3,0x5B,0x28,0x0C,0xB2,0x7C } }; // B7EB66A8-FE8A-4CFB-8B42-E35B280CB27C
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities>{ 0xDE5B52CA,0xE02E,0x40E9,{ 0x9E,0x5E,0x1B,0x48,0x8E,0x6A,0xAC,0xFC } }; // DE5B52CA-E02E-40E9-9E5E-1B488E6AACFC
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities>{ 0x09286B8B,0x9873,0x4D05,{ 0xBF,0xBE,0x47,0x27,0xA6,0x03,0x8F,0x69 } }; // 09286B8B-9873-4D05-BFBE-4727A6038F69
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IJournalPrintJob>{ 0x9F4F2864,0xF3F0,0x55D0,{ 0x8C,0x39,0x74,0xCC,0x91,0x78,0x3E,0xED } }; // 9F4F2864-F3F0-55D0-8C39-74CC91783EED
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IJournalPrinterCapabilities>{ 0x3B5CCC43,0xE047,0x4463,{ 0xBB,0x58,0x17,0xB5,0xBA,0x1D,0x80,0x56 } }; // 3B5CCC43-E047-4463-BB58-17B5BA1D8056
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IJournalPrinterCapabilities2>{ 0x03B0B645,0x33B8,0x533B,{ 0xBA,0xAA,0xA4,0x38,0x92,0x83,0xAB,0x0A } }; // 03B0B645-33B8-533B-BAAA-A4389283AB0A
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ILineDisplay>{ 0x24F5DF4E,0x3C99,0x44E2,{ 0xB7,0x3F,0xE5,0x1B,0xE3,0x63,0x7A,0x8C } }; // 24F5DF4E-3C99-44E2-B73F-E51BE3637A8C
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ILineDisplay2>{ 0xC296A628,0xEF44,0x40F3,{ 0xBD,0x1C,0xB0,0x4C,0x6A,0x5C,0xDC,0x7D } }; // C296A628-EF44-40F3-BD1C-B04C6A5CDC7D
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ILineDisplayAttributes>{ 0xC17DE99C,0x229A,0x4C14,{ 0xA6,0xF1,0xB4,0xE4,0xB1,0xFE,0xAD,0x92 } }; // C17DE99C-229A-4C14-A6F1-B4E4B1FEAD92
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ILineDisplayCapabilities>{ 0x5A15B5D1,0x8DC5,0x4B9C,{ 0x91,0x72,0x30,0x3E,0x47,0xB7,0x0C,0x55 } }; // 5A15B5D1-8DC5-4B9C-9172-303E47B70C55
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ILineDisplayCursor>{ 0xECDFFC45,0x754A,0x4E3B,{ 0xAB,0x2B,0x15,0x11,0x81,0x08,0x56,0x05 } }; // ECDFFC45-754A-4E3B-AB2B-151181085605
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ILineDisplayCursorAttributes>{ 0x4E2D54FE,0x4FFD,0x4190,{ 0xAA,0xE1,0xCE,0x28,0x5F,0x20,0xC8,0x96 } }; // 4E2D54FE-4FFD-4190-AAE1-CE285F20C896
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ILineDisplayCustomGlyphs>{ 0x2257F63C,0xF263,0x44F1,{ 0xA1,0xA0,0xE7,0x50,0xA6,0xA0,0xEC,0x54 } }; // 2257F63C-F263-44F1-A1A0-E750A6A0EC54
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ILineDisplayMarquee>{ 0xA3D33E3E,0xF46A,0x4B7A,{ 0xBC,0x21,0x53,0xEB,0x3B,0x57,0xF8,0xB4 } }; // A3D33E3E-F46A-4B7A-BC21-53EB3B57F8B4
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ILineDisplayStatics>{ 0x022DC0B6,0x11B0,0x4690,{ 0x95,0x47,0x0B,0x39,0xC5,0xAF,0x21,0x14 } }; // 022DC0B6-11B0-4690-9547-0B39C5AF2114
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ILineDisplayStatics2>{ 0x600C3F1C,0x77AB,0x4968,{ 0xA7,0xDE,0xC0,0x2F,0xF1,0x69,0xF2,0xCC } }; // 600C3F1C-77AB-4968-A7DE-C02FF169F2CC
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ILineDisplayStatisticsCategorySelector>{ 0xB521C46B,0x9274,0x4D24,{ 0x94,0xF3,0xB6,0x01,0x7B,0x83,0x24,0x44 } }; // B521C46B-9274-4D24-94F3-B6017B832444
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ILineDisplayStatusUpdatedEventArgs>{ 0xDDD57C1A,0x86FB,0x4EBA,{ 0x93,0xD1,0x6F,0x5E,0xDA,0x52,0xB7,0x52 } }; // DDD57C1A-86FB-4EBA-93D1-6F5EDA52B752
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ILineDisplayStoredBitmap>{ 0xF621515B,0xD81E,0x43BA,{ 0xBF,0x1B,0xBC,0xFA,0x3C,0x78,0x5B,0xA0 } }; // F621515B-D81E-43BA-BF1B-BCFA3C785BA0
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ILineDisplayWindow>{ 0xD21FEEF4,0x2364,0x4BE5,{ 0xBE,0xE1,0x85,0x16,0x80,0xAF,0x49,0x64 } }; // D21FEEF4-2364-4BE5-BEE1-851680AF4964
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ILineDisplayWindow2>{ 0xA95CE2E6,0xBDD8,0x4365,{ 0x8E,0x11,0xDE,0x94,0xDE,0x8D,0xFF,0x02 } }; // A95CE2E6-BDD8-4365-8E11-DE94DE8DFF02
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IMagneticStripeReader>{ 0x1A92B015,0x47C3,0x468A,{ 0x93,0x33,0x0C,0x65,0x17,0x57,0x48,0x83 } }; // 1A92B015-47C3-468A-9333-0C6517574883
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs>{ 0x0A4BBD51,0xC316,0x4910,{ 0x87,0xF3,0x7A,0x62,0xBA,0x86,0x2D,0x31 } }; // 0A4BBD51-C316-4910-87F3-7A62BA862D31
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs>{ 0x2E958823,0xA31A,0x4763,{ 0x88,0x2C,0x23,0x72,0x5E,0x39,0xB0,0x8E } }; // 2E958823-A31A-4763-882C-23725E39B08E
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities>{ 0x7128809C,0xC440,0x44A2,{ 0xA4,0x67,0x46,0x91,0x75,0xD0,0x28,0x96 } }; // 7128809C-C440-44A2-A467-469175D02896
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCardTypesStatics>{ 0x528F2C5D,0x2986,0x474F,{ 0x84,0x54,0x7C,0xCD,0x05,0x92,0x8D,0x5F } }; // 528F2C5D-2986-474F-8454-7CCD05928D5F
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderEncryptionAlgorithmsStatics>{ 0x53B57350,0xC3DB,0x4754,{ 0x9C,0x00,0x41,0x39,0x23,0x74,0xA1,0x09 } }; // 53B57350-C3DB-4754-9C00-41392374A109
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs>{ 0x1FEDF95D,0x2C84,0x41AD,{ 0xB7,0x78,0xF2,0x35,0x6A,0x78,0x9A,0xB1 } }; // 1FEDF95D-2C84-41AD-B778-F2356A789AB1
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderReport>{ 0x6A5B6047,0x99B0,0x4188,{ 0xBE,0xF1,0xED,0xDF,0x79,0xF7,0x8F,0xE6 } }; // 6A5B6047-99B0-4188-BEF1-EDDF79F78FE6
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatics>{ 0xC45FAB4A,0xEFD7,0x4760,{ 0xA5,0xCE,0x15,0xB0,0xE4,0x7E,0x94,0xEB } }; // C45FAB4A-EFD7-4760-A5CE-15B0E47E94EB
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatics2>{ 0x8CADC362,0xD667,0x48FA,{ 0x86,0xBC,0xF5,0xAE,0x11,0x89,0x26,0x2B } }; // 8CADC362-D667-48FA-86BC-F5AE1189262B
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatusUpdatedEventArgs>{ 0x09CC6BB0,0x3262,0x401D,{ 0x9E,0x8A,0xE8,0x0D,0x63,0x58,0x90,0x6B } }; // 09CC6BB0-3262-401D-9E8A-E80D6358906B
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderTrackData>{ 0x104CF671,0x4A9D,0x446E,{ 0xAB,0xC5,0x20,0x40,0x23,0x07,0xBA,0x36 } }; // 104CF671-4A9D-446E-ABC5-20402307BA36
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs>{ 0xAF0A5514,0x59CC,0x4A60,{ 0x99,0xE8,0x99,0xA5,0x3D,0xAC,0xE5,0xAA } }; // AF0A5514-59CC-4A60-99E8-99A53DACE5AA
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IPosPrinter>{ 0x2A03C10E,0x9A19,0x4A01,{ 0x99,0x4F,0x12,0xDF,0xAD,0x6A,0xDC,0xBF } }; // 2A03C10E-9A19-4A01-994F-12DFAD6ADCBF
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IPosPrinter2>{ 0x248475E8,0x8B98,0x5517,{ 0x8E,0x48,0x76,0x0E,0x86,0xF6,0x89,0x87 } }; // 248475E8-8B98-5517-8E48-760E86F68987
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IPosPrinterCapabilities>{ 0xCDE95721,0x4380,0x4985,{ 0xAD,0xC5,0x39,0xDB,0x30,0xCD,0x93,0xBC } }; // CDE95721-4380-4985-ADC5-39DB30CD93BC
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IPosPrinterCharacterSetIdsStatics>{ 0x5C709EFF,0x709A,0x4FE7,{ 0xB2,0x15,0x06,0xA7,0x48,0xA3,0x8B,0x39 } }; // 5C709EFF-709A-4FE7-B215-06A748A38B39
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IPosPrinterFontProperty>{ 0xA7F4E93A,0xF8AC,0x5F04,{ 0x84,0xD2,0x29,0xB1,0x6D,0x8A,0x63,0x3C } }; // A7F4E93A-F8AC-5F04-84D2-29B16D8A633C
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IPosPrinterJob>{ 0x9A94005C,0x0615,0x4591,{ 0xA5,0x8F,0x30,0xF8,0x7E,0xDF,0xE2,0xE4 } }; // 9A94005C-0615-4591-A58F-30F87EDFE2E4
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions>{ 0x0A2E16FD,0x1D02,0x5A58,{ 0x9D,0x59,0xBF,0xCD,0xE7,0x6F,0xDE,0x86 } }; // 0A2E16FD-1D02-5A58-9D59-BFCDE76FDE86
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IPosPrinterReleaseDeviceRequestedEventArgs>{ 0x2BCBA359,0x1CEF,0x40B2,{ 0x9E,0xCB,0xF9,0x27,0xF8,0x56,0xAE,0x3C } }; // 2BCBA359-1CEF-40B2-9ECB-F927F856AE3C
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IPosPrinterStatics>{ 0x8CE0D4EA,0x132F,0x4CDF,{ 0xA6,0x4A,0x2D,0x0D,0x7C,0x96,0xA8,0x5B } }; // 8CE0D4EA-132F-4CDF-A64A-2D0D7C96A85B
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IPosPrinterStatics2>{ 0xEECD2C1C,0xB0D0,0x42E7,{ 0xB1,0x37,0xB8,0x9B,0x16,0x24,0x4D,0x41 } }; // EECD2C1C-B0D0-42E7-B137-B89B16244D41
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IPosPrinterStatus>{ 0xD1F0C730,0xDA40,0x4328,{ 0xBF,0x76,0x51,0x56,0xFA,0x33,0xB7,0x47 } }; // D1F0C730-DA40-4328-BF76-5156FA33B747
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IPosPrinterStatusUpdatedEventArgs>{ 0x2EDB87DF,0x13A6,0x428D,{ 0xBA,0x81,0xB0,0xE7,0xC3,0xE5,0xA3,0xCD } }; // 2EDB87DF-13A6-428D-BA81-B0E7C3E5A3CD
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IReceiptOrSlipJob>{ 0x532199BE,0xC8C3,0x4DC2,{ 0x89,0xE9,0x5C,0x4A,0x37,0xB3,0x4D,0xDC } }; // 532199BE-C8C3-4DC2-89E9-5C4A37B34DDC
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IReceiptPrintJob>{ 0xAA96066E,0xACAD,0x4B79,{ 0x9D,0x0F,0xC0,0xCF,0xC0,0x8D,0xC7,0x7B } }; // AA96066E-ACAD-4B79-9D0F-C0CFC08DC77B
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IReceiptPrintJob2>{ 0x0CBC12E3,0x9E29,0x5179,{ 0xBC,0xD8,0x18,0x11,0xD3,0xB9,0xA1,0x0E } }; // 0CBC12E3-9E29-5179-BCD8-1811D3B9A10E
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities>{ 0xB8F0B58F,0x51A8,0x43FC,{ 0x9B,0xD5,0x8D,0xE2,0x72,0xA6,0x41,0x5B } }; // B8F0B58F-51A8-43FC-9BD5-8DE272A6415B
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities2>{ 0x20030638,0x8A2C,0x55AC,{ 0x9A,0x7B,0x75,0x76,0xD8,0x86,0x9E,0x99 } }; // 20030638-8A2C-55AC-9A7B-7576D8869E99
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ISlipPrintJob>{ 0x5D88F95D,0x6131,0x5A4B,{ 0xB7,0xD5,0x8E,0xF2,0xDA,0x7B,0x41,0x65 } }; // 5D88F95D-6131-5A4B-B7D5-8EF2DA7B4165
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ISlipPrinterCapabilities>{ 0x99B16399,0x488C,0x4157,{ 0x8A,0xC2,0x9F,0x57,0xF7,0x08,0xD3,0xDB } }; // 99B16399-488C-4157-8AC2-9F57F708D3DB
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::ISlipPrinterCapabilities2>{ 0x6FF89671,0x2D1A,0x5000,{ 0x87,0xC2,0xB0,0x85,0x1B,0xFD,0xF0,0x7E } }; // 6FF89671-2D1A-5000-87C2-B0851BFDF07E
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IUnifiedPosErrorData>{ 0x2B998C3A,0x555C,0x4889,{ 0x8E,0xD8,0xC5,0x99,0xBB,0x3A,0x71,0x2A } }; // 2B998C3A-555C-4889-8ED8-C599BB3A712A
    template <> inline constexpr guid guid_v<winrt::Windows::Devices::PointOfService::IUnifiedPosErrorDataFactory>{ 0x4B982551,0x1FFE,0x451B,{ 0xA3,0x68,0x63,0xE0,0xCE,0x46,0x5F,0x5A } }; // 4B982551-1FFE-451B-A368-63E0CE465F5A
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::BarcodeScanner>{ using type = winrt::Windows::Devices::PointOfService::IBarcodeScanner; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::BarcodeScannerCapabilities>{ using type = winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::BarcodeScannerDataReceivedEventArgs>{ using type = winrt::Windows::Devices::PointOfService::IBarcodeScannerDataReceivedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::BarcodeScannerErrorOccurredEventArgs>{ using type = winrt::Windows::Devices::PointOfService::IBarcodeScannerErrorOccurredEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::BarcodeScannerImagePreviewReceivedEventArgs>{ using type = winrt::Windows::Devices::PointOfService::IBarcodeScannerImagePreviewReceivedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::BarcodeScannerReport>{ using type = winrt::Windows::Devices::PointOfService::IBarcodeScannerReport; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::BarcodeScannerStatusUpdatedEventArgs>{ using type = winrt::Windows::Devices::PointOfService::IBarcodeScannerStatusUpdatedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::BarcodeSymbologyAttributes>{ using type = winrt::Windows::Devices::PointOfService::IBarcodeSymbologyAttributes; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::CashDrawer>{ using type = winrt::Windows::Devices::PointOfService::ICashDrawer; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::CashDrawerCapabilities>{ using type = winrt::Windows::Devices::PointOfService::ICashDrawerCapabilities; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::CashDrawerCloseAlarm>{ using type = winrt::Windows::Devices::PointOfService::ICashDrawerCloseAlarm; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::CashDrawerClosedEventArgs>{ using type = winrt::Windows::Devices::PointOfService::ICashDrawerEventSourceEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::CashDrawerEventSource>{ using type = winrt::Windows::Devices::PointOfService::ICashDrawerEventSource; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::CashDrawerOpenedEventArgs>{ using type = winrt::Windows::Devices::PointOfService::ICashDrawerEventSourceEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::CashDrawerStatus>{ using type = winrt::Windows::Devices::PointOfService::ICashDrawerStatus; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::CashDrawerStatusUpdatedEventArgs>{ using type = winrt::Windows::Devices::PointOfService::ICashDrawerStatusUpdatedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner>{ using type = winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScannerClosedEventArgs>{ using type = winrt::Windows::Devices::PointOfService::IClaimedBarcodeScannerClosedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::ClaimedCashDrawer>{ using type = winrt::Windows::Devices::PointOfService::IClaimedCashDrawer; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::ClaimedCashDrawerClosedEventArgs>{ using type = winrt::Windows::Devices::PointOfService::IClaimedCashDrawerClosedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::ClaimedJournalPrinter>{ using type = winrt::Windows::Devices::PointOfService::IClaimedJournalPrinter; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::ClaimedLineDisplay>{ using type = winrt::Windows::Devices::PointOfService::IClaimedLineDisplay; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::ClaimedLineDisplayClosedEventArgs>{ using type = winrt::Windows::Devices::PointOfService::IClaimedLineDisplayClosedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader>{ using type = winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReaderClosedEventArgs>{ using type = winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReaderClosedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::ClaimedPosPrinter>{ using type = winrt::Windows::Devices::PointOfService::IClaimedPosPrinter; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::ClaimedPosPrinterClosedEventArgs>{ using type = winrt::Windows::Devices::PointOfService::IClaimedPosPrinterClosedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::ClaimedReceiptPrinter>{ using type = winrt::Windows::Devices::PointOfService::IClaimedReceiptPrinter; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::ClaimedSlipPrinter>{ using type = winrt::Windows::Devices::PointOfService::IClaimedSlipPrinter; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::JournalPrintJob>{ using type = winrt::Windows::Devices::PointOfService::IPosPrinterJob; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::JournalPrinterCapabilities>{ using type = winrt::Windows::Devices::PointOfService::IJournalPrinterCapabilities; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::LineDisplay>{ using type = winrt::Windows::Devices::PointOfService::ILineDisplay; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::LineDisplayAttributes>{ using type = winrt::Windows::Devices::PointOfService::ILineDisplayAttributes; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::LineDisplayCapabilities>{ using type = winrt::Windows::Devices::PointOfService::ILineDisplayCapabilities; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::LineDisplayCursor>{ using type = winrt::Windows::Devices::PointOfService::ILineDisplayCursor; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::LineDisplayCursorAttributes>{ using type = winrt::Windows::Devices::PointOfService::ILineDisplayCursorAttributes; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::LineDisplayCustomGlyphs>{ using type = winrt::Windows::Devices::PointOfService::ILineDisplayCustomGlyphs; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::LineDisplayMarquee>{ using type = winrt::Windows::Devices::PointOfService::ILineDisplayMarquee; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::LineDisplayStatisticsCategorySelector>{ using type = winrt::Windows::Devices::PointOfService::ILineDisplayStatisticsCategorySelector; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::LineDisplayStatusUpdatedEventArgs>{ using type = winrt::Windows::Devices::PointOfService::ILineDisplayStatusUpdatedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::LineDisplayStoredBitmap>{ using type = winrt::Windows::Devices::PointOfService::ILineDisplayStoredBitmap; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::LineDisplayWindow>{ using type = winrt::Windows::Devices::PointOfService::ILineDisplayWindow; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::MagneticStripeReader>{ using type = winrt::Windows::Devices::PointOfService::IMagneticStripeReader; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::MagneticStripeReaderAamvaCardDataReceivedEventArgs>{ using type = winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::MagneticStripeReaderBankCardDataReceivedEventArgs>{ using type = winrt::Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::MagneticStripeReaderCapabilities>{ using type = winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::MagneticStripeReaderErrorOccurredEventArgs>{ using type = winrt::Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::MagneticStripeReaderReport>{ using type = winrt::Windows::Devices::PointOfService::IMagneticStripeReaderReport; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::MagneticStripeReaderStatusUpdatedEventArgs>{ using type = winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatusUpdatedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackData>{ using type = winrt::Windows::Devices::PointOfService::IMagneticStripeReaderTrackData; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::MagneticStripeReaderVendorSpecificCardDataReceivedEventArgs>{ using type = winrt::Windows::Devices::PointOfService::IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::PosPrinter>{ using type = winrt::Windows::Devices::PointOfService::IPosPrinter; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::PosPrinterCapabilities>{ using type = winrt::Windows::Devices::PointOfService::IPosPrinterCapabilities; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::PosPrinterFontProperty>{ using type = winrt::Windows::Devices::PointOfService::IPosPrinterFontProperty; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::PosPrinterPrintOptions>{ using type = winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::PosPrinterReleaseDeviceRequestedEventArgs>{ using type = winrt::Windows::Devices::PointOfService::IPosPrinterReleaseDeviceRequestedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::PosPrinterStatus>{ using type = winrt::Windows::Devices::PointOfService::IPosPrinterStatus; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::PosPrinterStatusUpdatedEventArgs>{ using type = winrt::Windows::Devices::PointOfService::IPosPrinterStatusUpdatedEventArgs; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::ReceiptPrintJob>{ using type = winrt::Windows::Devices::PointOfService::IReceiptPrintJob; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::ReceiptPrinterCapabilities>{ using type = winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::SlipPrintJob>{ using type = winrt::Windows::Devices::PointOfService::IReceiptOrSlipJob; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::SlipPrinterCapabilities>{ using type = winrt::Windows::Devices::PointOfService::ISlipPrinterCapabilities; };
    template <> struct default_interface<winrt::Windows::Devices::PointOfService::UnifiedPosErrorData>{ using type = winrt::Windows::Devices::PointOfService::IUnifiedPosErrorData; };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IBarcodeScanner>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
            virtual int32_t __stdcall get_Capabilities(void**) noexcept = 0;
            virtual int32_t __stdcall ClaimScannerAsync(void**) noexcept = 0;
            virtual int32_t __stdcall CheckHealthAsync(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetSupportedSymbologiesAsync(void**) noexcept = 0;
            virtual int32_t __stdcall IsSymbologySupportedAsync(uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall RetrieveStatisticsAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetSupportedProfiles(void**) noexcept = 0;
            virtual int32_t __stdcall IsProfileSupported(void*, bool*) noexcept = 0;
            virtual int32_t __stdcall add_StatusUpdated(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_StatusUpdated(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IBarcodeScanner2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_VideoDeviceId(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PowerReportingType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_IsStatisticsReportingSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsStatisticsUpdatingSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsImagePreviewSupported(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities1>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsSoftwareTriggerSupported(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsVideoPreviewSupported(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IBarcodeScannerDataReceivedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Report(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IBarcodeScannerErrorOccurredEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PartialInputData(void**) noexcept = 0;
            virtual int32_t __stdcall get_IsRetriable(bool*) noexcept = 0;
            virtual int32_t __stdcall get_ErrorData(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IBarcodeScannerImagePreviewReceivedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Preview(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IBarcodeScannerReport>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ScanDataType(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ScanData(void**) noexcept = 0;
            virtual int32_t __stdcall get_ScanDataLabel(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IBarcodeScannerReportFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateInstance(uint32_t, void*, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IBarcodeScannerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefaultAsync(void**) noexcept = 0;
            virtual int32_t __stdcall FromIdAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelector(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IBarcodeScannerStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDeviceSelectorWithConnectionTypes(uint32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IBarcodeScannerStatusUpdatedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ExtendedStatus(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Unknown(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Ean8(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Ean8Add2(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Ean8Add5(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Eanv(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_EanvAdd2(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_EanvAdd5(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Ean13(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Ean13Add2(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Ean13Add5(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Isbn(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_IsbnAdd5(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Ismn(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_IsmnAdd2(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_IsmnAdd5(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Issn(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_IssnAdd2(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_IssnAdd5(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Ean99(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Ean99Add2(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Ean99Add5(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Upca(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_UpcaAdd2(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_UpcaAdd5(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Upce(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_UpceAdd2(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_UpceAdd5(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_UpcCoupon(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_TfStd(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_TfDis(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_TfInt(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_TfInd(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_TfMat(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_TfIata(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Gs1DatabarType1(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Gs1DatabarType2(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Gs1DatabarType3(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Code39(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Code39Ex(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Trioptic39(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Code32(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Pzn(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Code93(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Code93Ex(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Code128(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Gs1128(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Gs1128Coupon(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_UccEan128(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Sisac(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Isbt(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Codabar(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Code11(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Msi(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Plessey(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Telepen(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Code16k(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_CodablockA(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_CodablockF(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Codablock128(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Code49(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Aztec(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_DataCode(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_DataMatrix(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_HanXin(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Maxicode(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_MicroPdf417(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_MicroQr(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Pdf417(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Qr(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_MsTag(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Ccab(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Ccc(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Tlc39(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_AusPost(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_CanPost(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ChinaPost(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_DutchKix(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_InfoMail(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ItalianPost25(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ItalianPost39(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_JapanPost(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_KoreanPost(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_SwedenPost(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_UkPost(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_UsIntelligent(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_UsIntelligentPkg(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_UsPlanet(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_UsPostNet(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Us4StateFics(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_OcrA(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_OcrB(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Micr(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ExtendedBase(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall GetName(uint32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Gs1DWCode(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IBarcodeSymbologyAttributes>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsCheckDigitValidationEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsCheckDigitValidationEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall get_IsCheckDigitValidationSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsCheckDigitTransmissionEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsCheckDigitTransmissionEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall get_IsCheckDigitTransmissionSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_DecodeLength1(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_DecodeLength1(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_DecodeLength2(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_DecodeLength2(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_DecodeLengthKind(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_DecodeLengthKind(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_IsDecodeLengthSupported(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ICashDrawer>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
            virtual int32_t __stdcall get_Capabilities(void**) noexcept = 0;
            virtual int32_t __stdcall get_Status(void**) noexcept = 0;
            virtual int32_t __stdcall get_IsDrawerOpen(bool*) noexcept = 0;
            virtual int32_t __stdcall get_DrawerEventSource(void**) noexcept = 0;
            virtual int32_t __stdcall ClaimDrawerAsync(void**) noexcept = 0;
            virtual int32_t __stdcall CheckHealthAsync(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetStatisticsAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall add_StatusUpdated(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_StatusUpdated(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ICashDrawerCapabilities>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PowerReportingType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_IsStatisticsReportingSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsStatisticsUpdatingSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsStatusReportingSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsStatusMultiDrawerDetectSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsDrawerOpenSensorAvailable(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ICashDrawerCloseAlarm>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_AlarmTimeout(int64_t) noexcept = 0;
            virtual int32_t __stdcall get_AlarmTimeout(int64_t*) noexcept = 0;
            virtual int32_t __stdcall put_BeepFrequency(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_BeepFrequency(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_BeepDuration(int64_t) noexcept = 0;
            virtual int32_t __stdcall get_BeepDuration(int64_t*) noexcept = 0;
            virtual int32_t __stdcall put_BeepDelay(int64_t) noexcept = 0;
            virtual int32_t __stdcall get_BeepDelay(int64_t*) noexcept = 0;
            virtual int32_t __stdcall add_AlarmTimeoutExpired(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_AlarmTimeoutExpired(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall StartAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ICashDrawerEventSource>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall add_DrawerClosed(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_DrawerClosed(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_DrawerOpened(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_DrawerOpened(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ICashDrawerEventSourceEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_CashDrawer(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ICashDrawerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefaultAsync(void**) noexcept = 0;
            virtual int32_t __stdcall FromIdAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelector(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ICashDrawerStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDeviceSelectorWithConnectionTypes(uint32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ICashDrawerStatus>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_StatusKind(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ExtendedStatus(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ICashDrawerStatusUpdatedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
            virtual int32_t __stdcall get_IsEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsDisabledOnDataReceived(bool) noexcept = 0;
            virtual int32_t __stdcall get_IsDisabledOnDataReceived(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsDecodeDataEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall get_IsDecodeDataEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall EnableAsync(void**) noexcept = 0;
            virtual int32_t __stdcall DisableAsync(void**) noexcept = 0;
            virtual int32_t __stdcall RetainDevice() noexcept = 0;
            virtual int32_t __stdcall SetActiveSymbologiesAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall ResetStatisticsAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall UpdateStatisticsAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall SetActiveProfileAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall add_DataReceived(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_DataReceived(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_TriggerPressed(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_TriggerPressed(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_TriggerReleased(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_TriggerReleased(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ReleaseDeviceRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ReleaseDeviceRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ImagePreviewReceived(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ImagePreviewReceived(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ErrorOccurred(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ErrorOccurred(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner1>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall StartSoftwareTriggerAsync(void**) noexcept = 0;
            virtual int32_t __stdcall StopSoftwareTriggerAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetSymbologyAttributesAsync(uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall SetSymbologyAttributesAsync(uint32_t, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ShowVideoPreviewAsync(void**) noexcept = 0;
            virtual int32_t __stdcall HideVideoPreview() noexcept = 0;
            virtual int32_t __stdcall put_IsVideoPreviewShownOnEnable(bool) noexcept = 0;
            virtual int32_t __stdcall get_IsVideoPreviewShownOnEnable(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner4>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall add_Closed(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Closed(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScannerClosedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IClaimedCashDrawer>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
            virtual int32_t __stdcall get_IsEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsDrawerOpen(bool*) noexcept = 0;
            virtual int32_t __stdcall get_CloseAlarm(void**) noexcept = 0;
            virtual int32_t __stdcall OpenDrawerAsync(void**) noexcept = 0;
            virtual int32_t __stdcall EnableAsync(void**) noexcept = 0;
            virtual int32_t __stdcall DisableAsync(void**) noexcept = 0;
            virtual int32_t __stdcall RetainDeviceAsync(void**) noexcept = 0;
            virtual int32_t __stdcall ResetStatisticsAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall UpdateStatisticsAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall add_ReleaseDeviceRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ReleaseDeviceRequested(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IClaimedCashDrawer2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall add_Closed(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Closed(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IClaimedCashDrawerClosedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IClaimedJournalPrinter>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateJob(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
            virtual int32_t __stdcall get_Capabilities(void**) noexcept = 0;
            virtual int32_t __stdcall get_PhysicalDeviceName(void**) noexcept = 0;
            virtual int32_t __stdcall get_PhysicalDeviceDescription(void**) noexcept = 0;
            virtual int32_t __stdcall get_DeviceControlDescription(void**) noexcept = 0;
            virtual int32_t __stdcall get_DeviceControlVersion(void**) noexcept = 0;
            virtual int32_t __stdcall get_DeviceServiceVersion(void**) noexcept = 0;
            virtual int32_t __stdcall get_DefaultWindow(void**) noexcept = 0;
            virtual int32_t __stdcall RetainDevice() noexcept = 0;
            virtual int32_t __stdcall add_ReleaseDeviceRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ReleaseDeviceRequested(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetStatisticsAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall CheckHealthAsync(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall CheckPowerStatusAsync(void**) noexcept = 0;
            virtual int32_t __stdcall add_StatusUpdated(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_StatusUpdated(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall get_SupportedScreenSizesInCharacters(void**) noexcept = 0;
            virtual int32_t __stdcall get_MaxBitmapSizeInPixels(winrt::Windows::Foundation::Size*) noexcept = 0;
            virtual int32_t __stdcall get_SupportedCharacterSets(void**) noexcept = 0;
            virtual int32_t __stdcall get_CustomGlyphs(void**) noexcept = 0;
            virtual int32_t __stdcall GetAttributes(void**) noexcept = 0;
            virtual int32_t __stdcall TryUpdateAttributesAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall TrySetDescriptorAsync(uint32_t, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall TryClearDescriptorsAsync(void**) noexcept = 0;
            virtual int32_t __stdcall TryCreateWindowAsync(winrt::Windows::Foundation::Rect, winrt::Windows::Foundation::Size, void**) noexcept = 0;
            virtual int32_t __stdcall TryStoreStorageFileBitmapAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall TryStoreStorageFileBitmapWithAlignmentAsync(void*, int32_t, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall TryStoreStorageFileBitmapWithAlignmentAndWidthAsync(void*, int32_t, int32_t, int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall add_Closed(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Closed(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IClaimedLineDisplayClosedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IClaimedLineDisplayStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall FromIdAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelector(void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelectorWithConnectionTypes(uint32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
            virtual int32_t __stdcall get_IsEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsDisabledOnDataReceived(bool) noexcept = 0;
            virtual int32_t __stdcall get_IsDisabledOnDataReceived(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsDecodeDataEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall get_IsDecodeDataEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsDeviceAuthenticated(bool*) noexcept = 0;
            virtual int32_t __stdcall put_DataEncryptionAlgorithm(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_DataEncryptionAlgorithm(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_TracksToRead(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_TracksToRead(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_IsTransmitSentinelsEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall get_IsTransmitSentinelsEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall EnableAsync(void**) noexcept = 0;
            virtual int32_t __stdcall DisableAsync(void**) noexcept = 0;
            virtual int32_t __stdcall RetainDevice() noexcept = 0;
            virtual int32_t __stdcall SetErrorReportingType(int32_t) noexcept = 0;
            virtual int32_t __stdcall RetrieveDeviceAuthenticationDataAsync(void**) noexcept = 0;
            virtual int32_t __stdcall AuthenticateDeviceAsync(uint32_t, uint8_t*, void**) noexcept = 0;
            virtual int32_t __stdcall DeAuthenticateDeviceAsync(uint32_t, uint8_t*, void**) noexcept = 0;
            virtual int32_t __stdcall UpdateKeyAsync(void*, void*, void**) noexcept = 0;
            virtual int32_t __stdcall ResetStatisticsAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall UpdateStatisticsAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall add_BankCardDataReceived(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_BankCardDataReceived(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_AamvaCardDataReceived(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_AamvaCardDataReceived(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_VendorSpecificDataReceived(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_VendorSpecificDataReceived(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ReleaseDeviceRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ReleaseDeviceRequested(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_ErrorOccurred(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ErrorOccurred(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall add_Closed(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Closed(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReaderClosedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IClaimedPosPrinter>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
            virtual int32_t __stdcall get_IsEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_CharacterSet(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_CharacterSet(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_IsCoverOpen(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsCharacterSetMappingEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall get_IsCharacterSetMappingEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_MapMode(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_MapMode(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Receipt(void**) noexcept = 0;
            virtual int32_t __stdcall get_Slip(void**) noexcept = 0;
            virtual int32_t __stdcall get_Journal(void**) noexcept = 0;
            virtual int32_t __stdcall EnableAsync(void**) noexcept = 0;
            virtual int32_t __stdcall DisableAsync(void**) noexcept = 0;
            virtual int32_t __stdcall RetainDeviceAsync(void**) noexcept = 0;
            virtual int32_t __stdcall ResetStatisticsAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall UpdateStatisticsAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall add_ReleaseDeviceRequested(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ReleaseDeviceRequested(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IClaimedPosPrinter2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall add_Closed(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Closed(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IClaimedPosPrinterClosedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IClaimedReceiptPrinter>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_SidewaysMaxLines(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_SidewaysMaxChars(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_LinesToPaperCut(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_PageSize(winrt::Windows::Foundation::Size*) noexcept = 0;
            virtual int32_t __stdcall get_PrintArea(winrt::Windows::Foundation::Rect*) noexcept = 0;
            virtual int32_t __stdcall CreateJob(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IClaimedSlipPrinter>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_SidewaysMaxLines(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_SidewaysMaxChars(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_MaxLines(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_LinesNearEndToEnd(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_PrintSide(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_PageSize(winrt::Windows::Foundation::Size*) noexcept = 0;
            virtual int32_t __stdcall get_PrintArea(winrt::Windows::Foundation::Rect*) noexcept = 0;
            virtual int32_t __stdcall OpenJaws() noexcept = 0;
            virtual int32_t __stdcall CloseJaws() noexcept = 0;
            virtual int32_t __stdcall InsertSlipAsync(int64_t, void**) noexcept = 0;
            virtual int32_t __stdcall RemoveSlipAsync(int64_t, void**) noexcept = 0;
            virtual int32_t __stdcall ChangePrintSide(int32_t) noexcept = 0;
            virtual int32_t __stdcall CreateJob(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_CharactersPerLine(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_CharactersPerLine(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_LineHeight(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_LineHeight(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_LineSpacing(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_LineSpacing(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_LineWidth(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_IsLetterQuality(bool) noexcept = 0;
            virtual int32_t __stdcall get_IsLetterQuality(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsPaperNearEnd(bool*) noexcept = 0;
            virtual int32_t __stdcall put_ColorCartridge(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_ColorCartridge(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_IsCoverOpen(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsCartridgeRemoved(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsCartridgeEmpty(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsHeadCleaning(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsPaperEmpty(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsReadyToPrint(bool*) noexcept = 0;
            virtual int32_t __stdcall ValidateData(void*, bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsPrinterPresent(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsDualColorSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_ColorCartridgeCapabilities(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_CartridgeSensors(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_IsBoldSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsItalicSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsUnderlineSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsDoubleHighPrintSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsDoubleWidePrintSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsDoubleHighDoubleWidePrintSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsPaperEmptySensorSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsPaperNearEndSensorSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_SupportedCharactersPerLine(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsBarcodeSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsBitmapSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsLeft90RotationSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsRight90RotationSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_Is180RotationSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsPrintAreaSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_RuledLineCapabilities(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_SupportedBarcodeRotations(void**) noexcept = 0;
            virtual int32_t __stdcall get_SupportedBitmapRotations(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IJournalPrintJob>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Print(void*, void*) noexcept = 0;
            virtual int32_t __stdcall FeedPaperByLine(int32_t) noexcept = 0;
            virtual int32_t __stdcall FeedPaperByMapModeUnit(int32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IJournalPrinterCapabilities>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IJournalPrinterCapabilities2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsReverseVideoSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsStrikethroughSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsSuperscriptSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsSubscriptSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsReversePaperFeedByLineSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsReversePaperFeedByMapModeUnitSupported(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ILineDisplay>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
            virtual int32_t __stdcall get_Capabilities(void**) noexcept = 0;
            virtual int32_t __stdcall get_PhysicalDeviceName(void**) noexcept = 0;
            virtual int32_t __stdcall get_PhysicalDeviceDescription(void**) noexcept = 0;
            virtual int32_t __stdcall get_DeviceControlDescription(void**) noexcept = 0;
            virtual int32_t __stdcall get_DeviceControlVersion(void**) noexcept = 0;
            virtual int32_t __stdcall get_DeviceServiceVersion(void**) noexcept = 0;
            virtual int32_t __stdcall ClaimAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ILineDisplay2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CheckPowerStatusAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ILineDisplayAttributes>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsPowerNotifyEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsPowerNotifyEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall get_Brightness(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_Brightness(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_BlinkRate(int64_t*) noexcept = 0;
            virtual int32_t __stdcall put_BlinkRate(int64_t) noexcept = 0;
            virtual int32_t __stdcall get_ScreenSizeInCharacters(winrt::Windows::Foundation::Size*) noexcept = 0;
            virtual int32_t __stdcall put_ScreenSizeInCharacters(winrt::Windows::Foundation::Size) noexcept = 0;
            virtual int32_t __stdcall get_CharacterSet(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_CharacterSet(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_IsCharacterSetMappingEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsCharacterSetMappingEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall get_CurrentWindow(void**) noexcept = 0;
            virtual int32_t __stdcall put_CurrentWindow(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ILineDisplayCapabilities>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsStatisticsReportingSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsStatisticsUpdatingSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_PowerReportingType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_CanChangeScreenSize(bool*) noexcept = 0;
            virtual int32_t __stdcall get_CanDisplayBitmaps(bool*) noexcept = 0;
            virtual int32_t __stdcall get_CanReadCharacterAtCursor(bool*) noexcept = 0;
            virtual int32_t __stdcall get_CanMapCharacterSets(bool*) noexcept = 0;
            virtual int32_t __stdcall get_CanDisplayCustomGlyphs(bool*) noexcept = 0;
            virtual int32_t __stdcall get_CanReverse(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_CanBlink(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_CanChangeBlinkRate(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsBrightnessSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsCursorSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsHorizontalMarqueeSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsVerticalMarqueeSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsInterCharacterWaitSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_SupportedDescriptors(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_SupportedWindows(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ILineDisplayCursor>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_CanCustomize(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsBlinkSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsBlockSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsHalfBlockSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsUnderlineSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsReverseSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsOtherSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall GetAttributes(void**) noexcept = 0;
            virtual int32_t __stdcall TryUpdateAttributesAsync(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ILineDisplayCursorAttributes>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsBlinkEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsBlinkEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall get_CursorType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_CursorType(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_IsAutoAdvanceEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsAutoAdvanceEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall get_Position(winrt::Windows::Foundation::Point*) noexcept = 0;
            virtual int32_t __stdcall put_Position(winrt::Windows::Foundation::Point) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ILineDisplayCustomGlyphs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_SizeInPixels(winrt::Windows::Foundation::Size*) noexcept = 0;
            virtual int32_t __stdcall get_SupportedGlyphCodes(void**) noexcept = 0;
            virtual int32_t __stdcall TryRedefineAsync(uint32_t, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ILineDisplayMarquee>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Format(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_Format(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_RepeatWaitInterval(int64_t*) noexcept = 0;
            virtual int32_t __stdcall put_RepeatWaitInterval(int64_t) noexcept = 0;
            virtual int32_t __stdcall get_ScrollWaitInterval(int64_t*) noexcept = 0;
            virtual int32_t __stdcall put_ScrollWaitInterval(int64_t) noexcept = 0;
            virtual int32_t __stdcall TryStartScrollingAsync(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall TryStopScrollingAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ILineDisplayStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall FromIdAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetDefaultAsync(void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelector(void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelectorWithConnectionTypes(uint32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ILineDisplayStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_StatisticsCategorySelector(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ILineDisplayStatisticsCategorySelector>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AllStatistics(void**) noexcept = 0;
            virtual int32_t __stdcall get_UnifiedPosStatistics(void**) noexcept = 0;
            virtual int32_t __stdcall get_ManufacturerStatistics(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ILineDisplayStatusUpdatedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ILineDisplayStoredBitmap>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_EscapeSequence(void**) noexcept = 0;
            virtual int32_t __stdcall TryDeleteAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ILineDisplayWindow>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_SizeInCharacters(winrt::Windows::Foundation::Size*) noexcept = 0;
            virtual int32_t __stdcall get_InterCharacterWaitInterval(int64_t*) noexcept = 0;
            virtual int32_t __stdcall put_InterCharacterWaitInterval(int64_t) noexcept = 0;
            virtual int32_t __stdcall TryRefreshAsync(void**) noexcept = 0;
            virtual int32_t __stdcall TryDisplayTextAsync(void*, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall TryDisplayTextAtPositionAsync(void*, int32_t, winrt::Windows::Foundation::Point, void**) noexcept = 0;
            virtual int32_t __stdcall TryDisplayTextNormalAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall TryScrollTextAsync(int32_t, uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall TryClearTextAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ILineDisplayWindow2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Cursor(void**) noexcept = 0;
            virtual int32_t __stdcall get_Marquee(void**) noexcept = 0;
            virtual int32_t __stdcall ReadCharacterAtCursorAsync(void**) noexcept = 0;
            virtual int32_t __stdcall TryDisplayStoredBitmapAtCursorAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall TryDisplayStorageFileBitmapAtCursorAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall TryDisplayStorageFileBitmapAtCursorWithAlignmentAsync(void*, int32_t, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall TryDisplayStorageFileBitmapAtCursorWithAlignmentAndWidthAsync(void*, int32_t, int32_t, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall TryDisplayStorageFileBitmapAtPointAsync(void*, winrt::Windows::Foundation::Point, void**) noexcept = 0;
            virtual int32_t __stdcall TryDisplayStorageFileBitmapAtPointWithWidthAsync(void*, winrt::Windows::Foundation::Point, int32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IMagneticStripeReader>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
            virtual int32_t __stdcall get_Capabilities(void**) noexcept = 0;
            virtual int32_t __stdcall get_SupportedCardTypes(uint32_t* __valueSize, uint32_t**) noexcept = 0;
            virtual int32_t __stdcall get_DeviceAuthenticationProtocol(int32_t*) noexcept = 0;
            virtual int32_t __stdcall CheckHealthAsync(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall ClaimReaderAsync(void**) noexcept = 0;
            virtual int32_t __stdcall RetrieveStatisticsAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetErrorReportingType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall add_StatusUpdated(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_StatusUpdated(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Report(void**) noexcept = 0;
            virtual int32_t __stdcall get_LicenseNumber(void**) noexcept = 0;
            virtual int32_t __stdcall get_ExpirationDate(void**) noexcept = 0;
            virtual int32_t __stdcall get_Restrictions(void**) noexcept = 0;
            virtual int32_t __stdcall get_Class(void**) noexcept = 0;
            virtual int32_t __stdcall get_Endorsements(void**) noexcept = 0;
            virtual int32_t __stdcall get_BirthDate(void**) noexcept = 0;
            virtual int32_t __stdcall get_FirstName(void**) noexcept = 0;
            virtual int32_t __stdcall get_Surname(void**) noexcept = 0;
            virtual int32_t __stdcall get_Suffix(void**) noexcept = 0;
            virtual int32_t __stdcall get_Gender(void**) noexcept = 0;
            virtual int32_t __stdcall get_HairColor(void**) noexcept = 0;
            virtual int32_t __stdcall get_EyeColor(void**) noexcept = 0;
            virtual int32_t __stdcall get_Height(void**) noexcept = 0;
            virtual int32_t __stdcall get_Weight(void**) noexcept = 0;
            virtual int32_t __stdcall get_Address(void**) noexcept = 0;
            virtual int32_t __stdcall get_City(void**) noexcept = 0;
            virtual int32_t __stdcall get_State(void**) noexcept = 0;
            virtual int32_t __stdcall get_PostalCode(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Report(void**) noexcept = 0;
            virtual int32_t __stdcall get_AccountNumber(void**) noexcept = 0;
            virtual int32_t __stdcall get_ExpirationDate(void**) noexcept = 0;
            virtual int32_t __stdcall get_ServiceCode(void**) noexcept = 0;
            virtual int32_t __stdcall get_Title(void**) noexcept = 0;
            virtual int32_t __stdcall get_FirstName(void**) noexcept = 0;
            virtual int32_t __stdcall get_MiddleInitial(void**) noexcept = 0;
            virtual int32_t __stdcall get_Surname(void**) noexcept = 0;
            virtual int32_t __stdcall get_Suffix(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_CardAuthentication(void**) noexcept = 0;
            virtual int32_t __stdcall get_SupportedEncryptionAlgorithms(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_AuthenticationLevel(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_IsIsoSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsJisOneSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsJisTwoSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_PowerReportingType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_IsStatisticsReportingSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsStatisticsUpdatingSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsTrackDataMaskingSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsTransmitSentinelsSupported(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCardTypesStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Unknown(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Bank(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Aamva(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ExtendedBase(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderEncryptionAlgorithmsStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_None(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_TripleDesDukpt(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ExtendedBase(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Track1Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Track2Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Track3Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Track4Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ErrorData(void**) noexcept = 0;
            virtual int32_t __stdcall get_PartialInputData(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderReport>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_CardType(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Track1(void**) noexcept = 0;
            virtual int32_t __stdcall get_Track2(void**) noexcept = 0;
            virtual int32_t __stdcall get_Track3(void**) noexcept = 0;
            virtual int32_t __stdcall get_Track4(void**) noexcept = 0;
            virtual int32_t __stdcall get_Properties(void**) noexcept = 0;
            virtual int32_t __stdcall get_CardAuthenticationData(void**) noexcept = 0;
            virtual int32_t __stdcall get_CardAuthenticationDataLength(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_AdditionalSecurityInformation(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefaultAsync(void**) noexcept = 0;
            virtual int32_t __stdcall FromIdAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelector(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDeviceSelectorWithConnectionTypes(uint32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatusUpdatedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ExtendedStatus(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderTrackData>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Data(void**) noexcept = 0;
            virtual int32_t __stdcall get_DiscretionaryData(void**) noexcept = 0;
            virtual int32_t __stdcall get_EncryptedData(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Report(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IPosPrinter>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DeviceId(void**) noexcept = 0;
            virtual int32_t __stdcall get_Capabilities(void**) noexcept = 0;
            virtual int32_t __stdcall get_SupportedCharacterSets(void**) noexcept = 0;
            virtual int32_t __stdcall get_SupportedTypeFaces(void**) noexcept = 0;
            virtual int32_t __stdcall get_Status(void**) noexcept = 0;
            virtual int32_t __stdcall ClaimPrinterAsync(void**) noexcept = 0;
            virtual int32_t __stdcall CheckHealthAsync(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetStatisticsAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall add_StatusUpdated(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_StatusUpdated(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IPosPrinter2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_SupportedBarcodeSymbologies(void**) noexcept = 0;
            virtual int32_t __stdcall GetFontProperty(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IPosPrinterCapabilities>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PowerReportingType(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_IsStatisticsReportingSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsStatisticsUpdatingSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_DefaultCharacterSet(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_HasCoverSensor(bool*) noexcept = 0;
            virtual int32_t __stdcall get_CanMapCharacterSet(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsTransactionSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_Receipt(void**) noexcept = 0;
            virtual int32_t __stdcall get_Slip(void**) noexcept = 0;
            virtual int32_t __stdcall get_Journal(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IPosPrinterCharacterSetIdsStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Utf16LE(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Ascii(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Ansi(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IPosPrinterFontProperty>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_TypeFace(void**) noexcept = 0;
            virtual int32_t __stdcall get_IsScalableToAnySize(bool*) noexcept = 0;
            virtual int32_t __stdcall get_CharacterSizes(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IPosPrinterJob>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Print(void*) noexcept = 0;
            virtual int32_t __stdcall PrintLine(void*) noexcept = 0;
            virtual int32_t __stdcall PrintNewline() noexcept = 0;
            virtual int32_t __stdcall ExecuteAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_TypeFace(void**) noexcept = 0;
            virtual int32_t __stdcall put_TypeFace(void*) noexcept = 0;
            virtual int32_t __stdcall get_CharacterHeight(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_CharacterHeight(uint32_t) noexcept = 0;
            virtual int32_t __stdcall get_Bold(bool*) noexcept = 0;
            virtual int32_t __stdcall put_Bold(bool) noexcept = 0;
            virtual int32_t __stdcall get_Italic(bool*) noexcept = 0;
            virtual int32_t __stdcall put_Italic(bool) noexcept = 0;
            virtual int32_t __stdcall get_Underline(bool*) noexcept = 0;
            virtual int32_t __stdcall put_Underline(bool) noexcept = 0;
            virtual int32_t __stdcall get_ReverseVideo(bool*) noexcept = 0;
            virtual int32_t __stdcall put_ReverseVideo(bool) noexcept = 0;
            virtual int32_t __stdcall get_Strikethrough(bool*) noexcept = 0;
            virtual int32_t __stdcall put_Strikethrough(bool) noexcept = 0;
            virtual int32_t __stdcall get_Superscript(bool*) noexcept = 0;
            virtual int32_t __stdcall put_Superscript(bool) noexcept = 0;
            virtual int32_t __stdcall get_Subscript(bool*) noexcept = 0;
            virtual int32_t __stdcall put_Subscript(bool) noexcept = 0;
            virtual int32_t __stdcall get_DoubleWide(bool*) noexcept = 0;
            virtual int32_t __stdcall put_DoubleWide(bool) noexcept = 0;
            virtual int32_t __stdcall get_DoubleHigh(bool*) noexcept = 0;
            virtual int32_t __stdcall put_DoubleHigh(bool) noexcept = 0;
            virtual int32_t __stdcall get_Alignment(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_Alignment(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_CharacterSet(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall put_CharacterSet(uint32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IPosPrinterReleaseDeviceRequestedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IPosPrinterStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDefaultAsync(void**) noexcept = 0;
            virtual int32_t __stdcall FromIdAsync(void*, void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelector(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IPosPrinterStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetDeviceSelectorWithConnectionTypes(uint32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IPosPrinterStatus>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_StatusKind(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ExtendedStatus(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IPosPrinterStatusUpdatedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Status(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IReceiptOrSlipJob>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall SetBarcodeRotation(int32_t) noexcept = 0;
            virtual int32_t __stdcall SetPrintRotation(int32_t, bool) noexcept = 0;
            virtual int32_t __stdcall SetPrintArea(winrt::Windows::Foundation::Rect) noexcept = 0;
            virtual int32_t __stdcall SetBitmap(uint32_t, void*, int32_t) noexcept = 0;
            virtual int32_t __stdcall SetBitmapCustomWidthStandardAlign(uint32_t, void*, int32_t, uint32_t) noexcept = 0;
            virtual int32_t __stdcall SetCustomAlignedBitmap(uint32_t, void*, uint32_t) noexcept = 0;
            virtual int32_t __stdcall SetBitmapCustomWidthCustomAlign(uint32_t, void*, uint32_t, uint32_t) noexcept = 0;
            virtual int32_t __stdcall PrintSavedBitmap(uint32_t) noexcept = 0;
            virtual int32_t __stdcall DrawRuledLine(void*, int32_t, uint32_t, int32_t, uint32_t) noexcept = 0;
            virtual int32_t __stdcall PrintBarcode(void*, uint32_t, uint32_t, uint32_t, int32_t, int32_t) noexcept = 0;
            virtual int32_t __stdcall PrintBarcodeCustomAlign(void*, uint32_t, uint32_t, uint32_t, int32_t, uint32_t) noexcept = 0;
            virtual int32_t __stdcall PrintBitmap(void*, int32_t) noexcept = 0;
            virtual int32_t __stdcall PrintBitmapCustomWidthStandardAlign(void*, int32_t, uint32_t) noexcept = 0;
            virtual int32_t __stdcall PrintCustomAlignedBitmap(void*, uint32_t) noexcept = 0;
            virtual int32_t __stdcall PrintBitmapCustomWidthCustomAlign(void*, uint32_t, uint32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IReceiptPrintJob>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall MarkFeed(int32_t) noexcept = 0;
            virtual int32_t __stdcall CutPaper(double) noexcept = 0;
            virtual int32_t __stdcall CutPaperDefault() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IReceiptPrintJob2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall StampPaper() noexcept = 0;
            virtual int32_t __stdcall Print(void*, void*) noexcept = 0;
            virtual int32_t __stdcall FeedPaperByLine(int32_t) noexcept = 0;
            virtual int32_t __stdcall FeedPaperByMapModeUnit(int32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_CanCutPaper(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsStampSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_MarkFeedCapabilities(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsReverseVideoSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsStrikethroughSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsSuperscriptSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsSubscriptSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsReversePaperFeedByLineSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsReversePaperFeedByMapModeUnitSupported(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ISlipPrintJob>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall Print(void*, void*) noexcept = 0;
            virtual int32_t __stdcall FeedPaperByLine(int32_t) noexcept = 0;
            virtual int32_t __stdcall FeedPaperByMapModeUnit(int32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ISlipPrinterCapabilities>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsFullLengthSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsBothSidesPrintingSupported(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::ISlipPrinterCapabilities2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsReverseVideoSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsStrikethroughSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsSuperscriptSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsSubscriptSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsReversePaperFeedByLineSupported(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsReversePaperFeedByMapModeUnitSupported(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IUnifiedPosErrorData>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Message(void**) noexcept = 0;
            virtual int32_t __stdcall get_Severity(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_Reason(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_ExtendedReason(uint32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::Devices::PointOfService::IUnifiedPosErrorDataFactory>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateInstance(void*, int32_t, int32_t, uint32_t, void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IBarcodeScanner
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::BarcodeScannerCapabilities) Capabilities() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner>) ClaimScannerAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) CheckHealthAsync(winrt::Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const& level) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Foundation::Collections::IVectorView<uint32_t>>) GetSupportedSymbologiesAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) IsSymbologySupportedAsync(uint32_t barcodeSymbology) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>) RetrieveStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) GetSupportedProfiles() const;
        WINRT_IMPL_AUTO(bool) IsProfileSupported(param::hstring const& profile) const;
        WINRT_IMPL_AUTO(winrt::event_token) StatusUpdated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::BarcodeScanner, winrt::Windows::Devices::PointOfService::BarcodeScannerStatusUpdatedEventArgs> const& handler) const;
        using StatusUpdated_revoker = impl::event_revoker<winrt::Windows::Devices::PointOfService::IBarcodeScanner, &impl::abi_t<winrt::Windows::Devices::PointOfService::IBarcodeScanner>::remove_StatusUpdated>;
        [[nodiscard]] StatusUpdated_revoker StatusUpdated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::BarcodeScanner, winrt::Windows::Devices::PointOfService::BarcodeScannerStatusUpdatedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) StatusUpdated(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IBarcodeScanner>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeScanner<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IBarcodeScanner2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) VideoDeviceId() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IBarcodeScanner2>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeScanner2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IBarcodeScannerCapabilities
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::UnifiedPosPowerReportingType) PowerReportingType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsStatisticsReportingSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsStatisticsUpdatingSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsImagePreviewSupported() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeScannerCapabilities<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IBarcodeScannerCapabilities1
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsSoftwareTriggerSupported() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities1>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeScannerCapabilities1<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IBarcodeScannerCapabilities2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsVideoPreviewSupported() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IBarcodeScannerCapabilities2>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeScannerCapabilities2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IBarcodeScannerDataReceivedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::BarcodeScannerReport) Report() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IBarcodeScannerDataReceivedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeScannerDataReceivedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IBarcodeScannerErrorOccurredEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::BarcodeScannerReport) PartialInputData() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsRetriable() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::UnifiedPosErrorData) ErrorData() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IBarcodeScannerErrorOccurredEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeScannerErrorOccurredEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IBarcodeScannerImagePreviewReceivedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IRandomAccessStreamWithContentType) Preview() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IBarcodeScannerImagePreviewReceivedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeScannerImagePreviewReceivedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IBarcodeScannerReport
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ScanDataType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) ScanData() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) ScanDataLabel() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IBarcodeScannerReport>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeScannerReport<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IBarcodeScannerReportFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::BarcodeScannerReport) CreateInstance(uint32_t scanDataType, winrt::Windows::Storage::Streams::IBuffer const& scanData, winrt::Windows::Storage::Streams::IBuffer const& scanDataLabel) const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IBarcodeScannerReportFactory>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeScannerReportFactory<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IBarcodeScannerStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::BarcodeScanner>) GetDefaultAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::BarcodeScanner>) FromIdAsync(param::hstring const& deviceId) const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IBarcodeScannerStatics>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeScannerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IBarcodeScannerStatics2
    {
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector(winrt::Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes) const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IBarcodeScannerStatics2>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeScannerStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IBarcodeScannerStatusUpdatedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::BarcodeScannerStatus) Status() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ExtendedStatus() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IBarcodeScannerStatusUpdatedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeScannerStatusUpdatedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Unknown() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Ean8() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Ean8Add2() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Ean8Add5() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Eanv() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) EanvAdd2() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) EanvAdd5() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Ean13() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Ean13Add2() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Ean13Add5() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Isbn() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) IsbnAdd5() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Ismn() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) IsmnAdd2() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) IsmnAdd5() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Issn() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) IssnAdd2() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) IssnAdd5() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Ean99() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Ean99Add2() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Ean99Add5() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Upca() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) UpcaAdd2() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) UpcaAdd5() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Upce() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) UpceAdd2() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) UpceAdd5() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) UpcCoupon() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) TfStd() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) TfDis() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) TfInt() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) TfInd() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) TfMat() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) TfIata() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Gs1DatabarType1() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Gs1DatabarType2() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Gs1DatabarType3() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Code39() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Code39Ex() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Trioptic39() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Code32() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Pzn() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Code93() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Code93Ex() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Code128() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Gs1128() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Gs1128Coupon() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) UccEan128() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Sisac() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Isbt() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Codabar() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Code11() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Msi() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Plessey() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Telepen() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Code16k() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) CodablockA() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) CodablockF() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Codablock128() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Code49() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Aztec() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) DataCode() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) DataMatrix() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) HanXin() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Maxicode() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MicroPdf417() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MicroQr() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Pdf417() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Qr() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MsTag() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Ccab() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Ccc() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Tlc39() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) AusPost() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) CanPost() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ChinaPost() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) DutchKix() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) InfoMail() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ItalianPost25() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ItalianPost39() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) JapanPost() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) KoreanPost() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) SwedenPost() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) UkPost() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) UsIntelligent() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) UsIntelligentPkg() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) UsPlanet() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) UsPostNet() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Us4StateFics() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) OcrA() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) OcrB() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Micr() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ExtendedBase() const;
        WINRT_IMPL_AUTO(hstring) GetName(uint32_t scanDataType) const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Gs1DWCode() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IBarcodeSymbologiesStatics2>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeSymbologiesStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsCheckDigitValidationEnabled() const;
        WINRT_IMPL_AUTO(void) IsCheckDigitValidationEnabled(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsCheckDigitValidationSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsCheckDigitTransmissionEnabled() const;
        WINRT_IMPL_AUTO(void) IsCheckDigitTransmissionEnabled(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsCheckDigitTransmissionSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) DecodeLength1() const;
        WINRT_IMPL_AUTO(void) DecodeLength1(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) DecodeLength2() const;
        WINRT_IMPL_AUTO(void) DecodeLength2(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::BarcodeSymbologyDecodeLengthKind) DecodeLengthKind() const;
        WINRT_IMPL_AUTO(void) DecodeLengthKind(winrt::Windows::Devices::PointOfService::BarcodeSymbologyDecodeLengthKind const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsDecodeLengthSupported() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IBarcodeSymbologyAttributes>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IBarcodeSymbologyAttributes<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ICashDrawer
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::CashDrawerCapabilities) Capabilities() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::CashDrawerStatus) Status() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsDrawerOpen() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::CashDrawerEventSource) DrawerEventSource() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::ClaimedCashDrawer>) ClaimDrawerAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) CheckHealthAsync(winrt::Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const& level) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) GetStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const;
        WINRT_IMPL_AUTO(winrt::event_token) StatusUpdated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::CashDrawer, winrt::Windows::Devices::PointOfService::CashDrawerStatusUpdatedEventArgs> const& handler) const;
        using StatusUpdated_revoker = impl::event_revoker<winrt::Windows::Devices::PointOfService::ICashDrawer, &impl::abi_t<winrt::Windows::Devices::PointOfService::ICashDrawer>::remove_StatusUpdated>;
        [[nodiscard]] StatusUpdated_revoker StatusUpdated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::CashDrawer, winrt::Windows::Devices::PointOfService::CashDrawerStatusUpdatedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) StatusUpdated(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ICashDrawer>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ICashDrawer<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ICashDrawerCapabilities
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::UnifiedPosPowerReportingType) PowerReportingType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsStatisticsReportingSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsStatisticsUpdatingSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsStatusReportingSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsStatusMultiDrawerDetectSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsDrawerOpenSensorAvailable() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ICashDrawerCapabilities>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ICashDrawerCapabilities<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm
    {
        WINRT_IMPL_AUTO(void) AlarmTimeout(winrt::Windows::Foundation::TimeSpan const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) AlarmTimeout() const;
        WINRT_IMPL_AUTO(void) BeepFrequency(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) BeepFrequency() const;
        WINRT_IMPL_AUTO(void) BeepDuration(winrt::Windows::Foundation::TimeSpan const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) BeepDuration() const;
        WINRT_IMPL_AUTO(void) BeepDelay(winrt::Windows::Foundation::TimeSpan const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) BeepDelay() const;
        WINRT_IMPL_AUTO(winrt::event_token) AlarmTimeoutExpired(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::CashDrawerCloseAlarm, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using AlarmTimeoutExpired_revoker = impl::event_revoker<winrt::Windows::Devices::PointOfService::ICashDrawerCloseAlarm, &impl::abi_t<winrt::Windows::Devices::PointOfService::ICashDrawerCloseAlarm>::remove_AlarmTimeoutExpired>;
        [[nodiscard]] AlarmTimeoutExpired_revoker AlarmTimeoutExpired(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::CashDrawerCloseAlarm, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) AlarmTimeoutExpired(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) StartAsync() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ICashDrawerCloseAlarm>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ICashDrawerCloseAlarm<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ICashDrawerEventSource
    {
        WINRT_IMPL_AUTO(winrt::event_token) DrawerClosed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::CashDrawerEventSource, winrt::Windows::Devices::PointOfService::CashDrawerClosedEventArgs> const& handler) const;
        using DrawerClosed_revoker = impl::event_revoker<winrt::Windows::Devices::PointOfService::ICashDrawerEventSource, &impl::abi_t<winrt::Windows::Devices::PointOfService::ICashDrawerEventSource>::remove_DrawerClosed>;
        [[nodiscard]] DrawerClosed_revoker DrawerClosed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::CashDrawerEventSource, winrt::Windows::Devices::PointOfService::CashDrawerClosedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) DrawerClosed(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) DrawerOpened(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::CashDrawerEventSource, winrt::Windows::Devices::PointOfService::CashDrawerOpenedEventArgs> const& handler) const;
        using DrawerOpened_revoker = impl::event_revoker<winrt::Windows::Devices::PointOfService::ICashDrawerEventSource, &impl::abi_t<winrt::Windows::Devices::PointOfService::ICashDrawerEventSource>::remove_DrawerOpened>;
        [[nodiscard]] DrawerOpened_revoker DrawerOpened(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::CashDrawerEventSource, winrt::Windows::Devices::PointOfService::CashDrawerOpenedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) DrawerOpened(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ICashDrawerEventSource>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ICashDrawerEventSource<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ICashDrawerEventSourceEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::CashDrawer) CashDrawer() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ICashDrawerEventSourceEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ICashDrawerEventSourceEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ICashDrawerStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::CashDrawer>) GetDefaultAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::CashDrawer>) FromIdAsync(param::hstring const& deviceId) const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ICashDrawerStatics>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ICashDrawerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ICashDrawerStatics2
    {
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector(winrt::Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes) const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ICashDrawerStatics2>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ICashDrawerStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ICashDrawerStatus
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::CashDrawerStatusKind) StatusKind() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ExtendedStatus() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ICashDrawerStatus>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ICashDrawerStatus<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ICashDrawerStatusUpdatedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::CashDrawerStatus) Status() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ICashDrawerStatusUpdatedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ICashDrawerStatusUpdatedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsEnabled() const;
        WINRT_IMPL_AUTO(void) IsDisabledOnDataReceived(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsDisabledOnDataReceived() const;
        WINRT_IMPL_AUTO(void) IsDecodeDataEnabled(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsDecodeDataEnabled() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) EnableAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) DisableAsync() const;
        WINRT_IMPL_AUTO(void) RetainDevice() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) SetActiveSymbologiesAsync(param::async_iterable<uint32_t> const& symbologies) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ResetStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) UpdateStatisticsAsync(param::async_iterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& statistics) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) SetActiveProfileAsync(param::hstring const& profile) const;
        WINRT_IMPL_AUTO(winrt::event_token) DataReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner, winrt::Windows::Devices::PointOfService::BarcodeScannerDataReceivedEventArgs> const& handler) const;
        using DataReceived_revoker = impl::event_revoker<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner, &impl::abi_t<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner>::remove_DataReceived>;
        [[nodiscard]] DataReceived_revoker DataReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner, winrt::Windows::Devices::PointOfService::BarcodeScannerDataReceivedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) DataReceived(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) TriggerPressed(winrt::Windows::Foundation::EventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner> const& handler) const;
        using TriggerPressed_revoker = impl::event_revoker<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner, &impl::abi_t<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner>::remove_TriggerPressed>;
        [[nodiscard]] TriggerPressed_revoker TriggerPressed(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner> const& handler) const;
        WINRT_IMPL_AUTO(void) TriggerPressed(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) TriggerReleased(winrt::Windows::Foundation::EventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner> const& handler) const;
        using TriggerReleased_revoker = impl::event_revoker<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner, &impl::abi_t<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner>::remove_TriggerReleased>;
        [[nodiscard]] TriggerReleased_revoker TriggerReleased(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner> const& handler) const;
        WINRT_IMPL_AUTO(void) TriggerReleased(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ReleaseDeviceRequested(winrt::Windows::Foundation::EventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner> const& handler) const;
        using ReleaseDeviceRequested_revoker = impl::event_revoker<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner, &impl::abi_t<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner>::remove_ReleaseDeviceRequested>;
        [[nodiscard]] ReleaseDeviceRequested_revoker ReleaseDeviceRequested(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner> const& handler) const;
        WINRT_IMPL_AUTO(void) ReleaseDeviceRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ImagePreviewReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner, winrt::Windows::Devices::PointOfService::BarcodeScannerImagePreviewReceivedEventArgs> const& handler) const;
        using ImagePreviewReceived_revoker = impl::event_revoker<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner, &impl::abi_t<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner>::remove_ImagePreviewReceived>;
        [[nodiscard]] ImagePreviewReceived_revoker ImagePreviewReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner, winrt::Windows::Devices::PointOfService::BarcodeScannerImagePreviewReceivedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ImagePreviewReceived(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ErrorOccurred(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner, winrt::Windows::Devices::PointOfService::BarcodeScannerErrorOccurredEventArgs> const& handler) const;
        using ErrorOccurred_revoker = impl::event_revoker<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner, &impl::abi_t<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner>::remove_ErrorOccurred>;
        [[nodiscard]] ErrorOccurred_revoker ErrorOccurred(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner, winrt::Windows::Devices::PointOfService::BarcodeScannerErrorOccurredEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ErrorOccurred(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner1
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) StartSoftwareTriggerAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) StopSoftwareTriggerAsync() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner1>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner1<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::BarcodeSymbologyAttributes>) GetSymbologyAttributesAsync(uint32_t barcodeSymbology) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) SetSymbologyAttributesAsync(uint32_t barcodeSymbology, winrt::Windows::Devices::PointOfService::BarcodeSymbologyAttributes const& attributes) const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner2>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner3
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) ShowVideoPreviewAsync() const;
        WINRT_IMPL_AUTO(void) HideVideoPreview() const;
        WINRT_IMPL_AUTO(void) IsVideoPreviewShownOnEnable(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsVideoPreviewShownOnEnable() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner3>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner3<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner4
    {
        WINRT_IMPL_AUTO(winrt::event_token) Closed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner, winrt::Windows::Devices::PointOfService::ClaimedBarcodeScannerClosedEventArgs> const& handler) const;
        using Closed_revoker = impl::event_revoker<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner4, &impl::abi_t<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner4>::remove_Closed>;
        [[nodiscard]] Closed_revoker Closed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedBarcodeScanner, winrt::Windows::Devices::PointOfService::ClaimedBarcodeScannerClosedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) Closed(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScanner4>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedBarcodeScanner4<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IClaimedBarcodeScannerClosedEventArgs
    {
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IClaimedBarcodeScannerClosedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedBarcodeScannerClosedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IClaimedCashDrawer
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsEnabled() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsDrawerOpen() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::CashDrawerCloseAlarm) CloseAlarm() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) OpenDrawerAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) EnableAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) DisableAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) RetainDeviceAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) ResetStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) UpdateStatisticsAsync(param::async_iterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& statistics) const;
        WINRT_IMPL_AUTO(winrt::event_token) ReleaseDeviceRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedCashDrawer, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using ReleaseDeviceRequested_revoker = impl::event_revoker<winrt::Windows::Devices::PointOfService::IClaimedCashDrawer, &impl::abi_t<winrt::Windows::Devices::PointOfService::IClaimedCashDrawer>::remove_ReleaseDeviceRequested>;
        [[nodiscard]] ReleaseDeviceRequested_revoker ReleaseDeviceRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedCashDrawer, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) ReleaseDeviceRequested(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IClaimedCashDrawer>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedCashDrawer<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IClaimedCashDrawer2
    {
        WINRT_IMPL_AUTO(winrt::event_token) Closed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedCashDrawer, winrt::Windows::Devices::PointOfService::ClaimedCashDrawerClosedEventArgs> const& handler) const;
        using Closed_revoker = impl::event_revoker<winrt::Windows::Devices::PointOfService::IClaimedCashDrawer2, &impl::abi_t<winrt::Windows::Devices::PointOfService::IClaimedCashDrawer2>::remove_Closed>;
        [[nodiscard]] Closed_revoker Closed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedCashDrawer, winrt::Windows::Devices::PointOfService::ClaimedCashDrawerClosedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) Closed(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IClaimedCashDrawer2>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedCashDrawer2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IClaimedCashDrawerClosedEventArgs
    {
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IClaimedCashDrawerClosedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedCashDrawerClosedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IClaimedJournalPrinter
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::JournalPrintJob) CreateJob() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IClaimedJournalPrinter>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedJournalPrinter<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IClaimedLineDisplay
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayCapabilities) Capabilities() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) PhysicalDeviceName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) PhysicalDeviceDescription() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceControlDescription() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceControlVersion() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceServiceVersion() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayWindow) DefaultWindow() const;
        WINRT_IMPL_AUTO(void) RetainDevice() const;
        WINRT_IMPL_AUTO(winrt::event_token) ReleaseDeviceRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedLineDisplay, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using ReleaseDeviceRequested_revoker = impl::event_revoker<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay, &impl::abi_t<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay>::remove_ReleaseDeviceRequested>;
        [[nodiscard]] ReleaseDeviceRequested_revoker ReleaseDeviceRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedLineDisplay, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) ReleaseDeviceRequested(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedLineDisplay<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IClaimedLineDisplay2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) GetStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) CheckHealthAsync(winrt::Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const& level) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplayPowerStatus>) CheckPowerStatusAsync() const;
        WINRT_IMPL_AUTO(winrt::event_token) StatusUpdated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedLineDisplay, winrt::Windows::Devices::PointOfService::LineDisplayStatusUpdatedEventArgs> const& handler) const;
        using StatusUpdated_revoker = impl::event_revoker<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay2, &impl::abi_t<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay2>::remove_StatusUpdated>;
        [[nodiscard]] StatusUpdated_revoker StatusUpdated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedLineDisplay, winrt::Windows::Devices::PointOfService::LineDisplayStatusUpdatedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) StatusUpdated(winrt::event_token const& token) const noexcept;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Foundation::Size>) SupportedScreenSizesInCharacters() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) MaxBitmapSizeInPixels() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<int32_t>) SupportedCharacterSets() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayCustomGlyphs) CustomGlyphs() const;
        WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayAttributes) GetAttributes() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TryUpdateAttributesAsync(winrt::Windows::Devices::PointOfService::LineDisplayAttributes const& attributes) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TrySetDescriptorAsync(uint32_t descriptor, winrt::Windows::Devices::PointOfService::LineDisplayDescriptorState const& descriptorState) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TryClearDescriptorsAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplayWindow>) TryCreateWindowAsync(winrt::Windows::Foundation::Rect const& viewport, winrt::Windows::Foundation::Size const& windowSize) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplayStoredBitmap>) TryStoreStorageFileBitmapAsync(winrt::Windows::Storage::StorageFile const& bitmap) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplayStoredBitmap>) TryStoreStorageFileBitmapAsync(winrt::Windows::Storage::StorageFile const& bitmap, winrt::Windows::Devices::PointOfService::LineDisplayHorizontalAlignment const& horizontalAlignment, winrt::Windows::Devices::PointOfService::LineDisplayVerticalAlignment const& verticalAlignment) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplayStoredBitmap>) TryStoreStorageFileBitmapAsync(winrt::Windows::Storage::StorageFile const& bitmap, winrt::Windows::Devices::PointOfService::LineDisplayHorizontalAlignment const& horizontalAlignment, winrt::Windows::Devices::PointOfService::LineDisplayVerticalAlignment const& verticalAlignment, int32_t widthInPixels) const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay2>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedLineDisplay2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IClaimedLineDisplay3
    {
        WINRT_IMPL_AUTO(winrt::event_token) Closed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedLineDisplay, winrt::Windows::Devices::PointOfService::ClaimedLineDisplayClosedEventArgs> const& handler) const;
        using Closed_revoker = impl::event_revoker<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay3, &impl::abi_t<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay3>::remove_Closed>;
        [[nodiscard]] Closed_revoker Closed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedLineDisplay, winrt::Windows::Devices::PointOfService::ClaimedLineDisplayClosedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) Closed(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IClaimedLineDisplay3>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedLineDisplay3<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IClaimedLineDisplayClosedEventArgs
    {
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IClaimedLineDisplayClosedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedLineDisplayClosedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IClaimedLineDisplayStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::ClaimedLineDisplay>) FromIdAsync(param::hstring const& deviceId) const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector() const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector(winrt::Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes) const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IClaimedLineDisplayStatics>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedLineDisplayStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsEnabled() const;
        WINRT_IMPL_AUTO(void) IsDisabledOnDataReceived(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsDisabledOnDataReceived() const;
        WINRT_IMPL_AUTO(void) IsDecodeDataEnabled(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsDecodeDataEnabled() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsDeviceAuthenticated() const;
        WINRT_IMPL_AUTO(void) DataEncryptionAlgorithm(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) DataEncryptionAlgorithm() const;
        WINRT_IMPL_AUTO(void) TracksToRead(winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackIds const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackIds) TracksToRead() const;
        WINRT_IMPL_AUTO(void) IsTransmitSentinelsEnabled(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsTransmitSentinelsEnabled() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) EnableAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) DisableAsync() const;
        WINRT_IMPL_AUTO(void) RetainDevice() const;
        WINRT_IMPL_AUTO(void) SetErrorReportingType(winrt::Windows::Devices::PointOfService::MagneticStripeReaderErrorReportingType const& value) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>) RetrieveDeviceAuthenticationDataAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) AuthenticateDeviceAsync(array_view<uint8_t const> responseToken) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) DeAuthenticateDeviceAsync(array_view<uint8_t const> responseToken) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) UpdateKeyAsync(param::hstring const& key, param::hstring const& keyName) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ResetStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) UpdateStatisticsAsync(param::async_iterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& statistics) const;
        WINRT_IMPL_AUTO(winrt::event_token) BankCardDataReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader, winrt::Windows::Devices::PointOfService::MagneticStripeReaderBankCardDataReceivedEventArgs> const& handler) const;
        using BankCardDataReceived_revoker = impl::event_revoker<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader, &impl::abi_t<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader>::remove_BankCardDataReceived>;
        [[nodiscard]] BankCardDataReceived_revoker BankCardDataReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader, winrt::Windows::Devices::PointOfService::MagneticStripeReaderBankCardDataReceivedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) BankCardDataReceived(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) AamvaCardDataReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader, winrt::Windows::Devices::PointOfService::MagneticStripeReaderAamvaCardDataReceivedEventArgs> const& handler) const;
        using AamvaCardDataReceived_revoker = impl::event_revoker<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader, &impl::abi_t<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader>::remove_AamvaCardDataReceived>;
        [[nodiscard]] AamvaCardDataReceived_revoker AamvaCardDataReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader, winrt::Windows::Devices::PointOfService::MagneticStripeReaderAamvaCardDataReceivedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) AamvaCardDataReceived(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) VendorSpecificDataReceived(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader, winrt::Windows::Devices::PointOfService::MagneticStripeReaderVendorSpecificCardDataReceivedEventArgs> const& handler) const;
        using VendorSpecificDataReceived_revoker = impl::event_revoker<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader, &impl::abi_t<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader>::remove_VendorSpecificDataReceived>;
        [[nodiscard]] VendorSpecificDataReceived_revoker VendorSpecificDataReceived(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader, winrt::Windows::Devices::PointOfService::MagneticStripeReaderVendorSpecificCardDataReceivedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) VendorSpecificDataReceived(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ReleaseDeviceRequested(winrt::Windows::Foundation::EventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader> const& handler) const;
        using ReleaseDeviceRequested_revoker = impl::event_revoker<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader, &impl::abi_t<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader>::remove_ReleaseDeviceRequested>;
        [[nodiscard]] ReleaseDeviceRequested_revoker ReleaseDeviceRequested(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader> const& handler) const;
        WINRT_IMPL_AUTO(void) ReleaseDeviceRequested(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) ErrorOccurred(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader, winrt::Windows::Devices::PointOfService::MagneticStripeReaderErrorOccurredEventArgs> const& handler) const;
        using ErrorOccurred_revoker = impl::event_revoker<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader, &impl::abi_t<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader>::remove_ErrorOccurred>;
        [[nodiscard]] ErrorOccurred_revoker ErrorOccurred(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader, winrt::Windows::Devices::PointOfService::MagneticStripeReaderErrorOccurredEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ErrorOccurred(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader2
    {
        WINRT_IMPL_AUTO(winrt::event_token) Closed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader, winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReaderClosedEventArgs> const& handler) const;
        using Closed_revoker = impl::event_revoker<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader2, &impl::abi_t<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader2>::remove_Closed>;
        [[nodiscard]] Closed_revoker Closed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader, winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReaderClosedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) Closed(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReader2>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReader2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReaderClosedEventArgs
    {
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IClaimedMagneticStripeReaderClosedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedMagneticStripeReaderClosedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IClaimedPosPrinter
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsEnabled() const;
        WINRT_IMPL_AUTO(void) CharacterSet(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) CharacterSet() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsCoverOpen() const;
        WINRT_IMPL_AUTO(void) IsCharacterSetMappingEnabled(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsCharacterSetMappingEnabled() const;
        WINRT_IMPL_AUTO(void) MapMode(winrt::Windows::Devices::PointOfService::PosPrinterMapMode const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::PosPrinterMapMode) MapMode() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::ClaimedReceiptPrinter) Receipt() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::ClaimedSlipPrinter) Slip() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::ClaimedJournalPrinter) Journal() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) EnableAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) DisableAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) RetainDeviceAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) ResetStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) UpdateStatisticsAsync(param::async_iterable<winrt::Windows::Foundation::Collections::IKeyValuePair<hstring, hstring>> const& statistics) const;
        WINRT_IMPL_AUTO(winrt::event_token) ReleaseDeviceRequested(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedPosPrinter, winrt::Windows::Devices::PointOfService::PosPrinterReleaseDeviceRequestedEventArgs> const& handler) const;
        using ReleaseDeviceRequested_revoker = impl::event_revoker<winrt::Windows::Devices::PointOfService::IClaimedPosPrinter, &impl::abi_t<winrt::Windows::Devices::PointOfService::IClaimedPosPrinter>::remove_ReleaseDeviceRequested>;
        [[nodiscard]] ReleaseDeviceRequested_revoker ReleaseDeviceRequested(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedPosPrinter, winrt::Windows::Devices::PointOfService::PosPrinterReleaseDeviceRequestedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) ReleaseDeviceRequested(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IClaimedPosPrinter>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedPosPrinter<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IClaimedPosPrinter2
    {
        WINRT_IMPL_AUTO(winrt::event_token) Closed(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedPosPrinter, winrt::Windows::Devices::PointOfService::ClaimedPosPrinterClosedEventArgs> const& handler) const;
        using Closed_revoker = impl::event_revoker<winrt::Windows::Devices::PointOfService::IClaimedPosPrinter2, &impl::abi_t<winrt::Windows::Devices::PointOfService::IClaimedPosPrinter2>::remove_Closed>;
        [[nodiscard]] Closed_revoker Closed(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::ClaimedPosPrinter, winrt::Windows::Devices::PointOfService::ClaimedPosPrinterClosedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) Closed(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IClaimedPosPrinter2>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedPosPrinter2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IClaimedPosPrinterClosedEventArgs
    {
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IClaimedPosPrinterClosedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedPosPrinterClosedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IClaimedReceiptPrinter
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) SidewaysMaxLines() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) SidewaysMaxChars() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) LinesToPaperCut() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) PageSize() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) PrintArea() const;
        WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::ReceiptPrintJob) CreateJob() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IClaimedReceiptPrinter>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedReceiptPrinter<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IClaimedSlipPrinter
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) SidewaysMaxLines() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) SidewaysMaxChars() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MaxLines() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) LinesNearEndToEnd() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::PosPrinterPrintSide) PrintSide() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) PageSize() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) PrintArea() const;
        WINRT_IMPL_AUTO(void) OpenJaws() const;
        WINRT_IMPL_AUTO(void) CloseJaws() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) InsertSlipAsync(winrt::Windows::Foundation::TimeSpan const& timeout) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) RemoveSlipAsync(winrt::Windows::Foundation::TimeSpan const& timeout) const;
        WINRT_IMPL_AUTO(void) ChangePrintSide(winrt::Windows::Devices::PointOfService::PosPrinterPrintSide const& printSide) const;
        WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::SlipPrintJob) CreateJob() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IClaimedSlipPrinter>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IClaimedSlipPrinter<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation
    {
        WINRT_IMPL_AUTO(void) CharactersPerLine(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) CharactersPerLine() const;
        WINRT_IMPL_AUTO(void) LineHeight(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) LineHeight() const;
        WINRT_IMPL_AUTO(void) LineSpacing(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) LineSpacing() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) LineWidth() const;
        WINRT_IMPL_AUTO(void) IsLetterQuality(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsLetterQuality() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsPaperNearEnd() const;
        WINRT_IMPL_AUTO(void) ColorCartridge(winrt::Windows::Devices::PointOfService::PosPrinterColorCartridge const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::PosPrinterColorCartridge) ColorCartridge() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsCoverOpen() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsCartridgeRemoved() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsCartridgeEmpty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsHeadCleaning() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsPaperEmpty() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsReadyToPrint() const;
        WINRT_IMPL_AUTO(bool) ValidateData(param::hstring const& data) const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ICommonClaimedPosPrinterStation>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ICommonClaimedPosPrinterStation<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsPrinterPresent() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsDualColorSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::PosPrinterColorCapabilities) ColorCartridgeCapabilities() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::PosPrinterCartridgeSensors) CartridgeSensors() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsBoldSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsItalicSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsUnderlineSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsDoubleHighPrintSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsDoubleWidePrintSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsDoubleHighDoubleWidePrintSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsPaperEmptySensorSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsPaperNearEndSensorSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<uint32_t>) SupportedCharactersPerLine() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ICommonPosPrintStationCapabilities>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ICommonPosPrintStationCapabilities<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ICommonReceiptSlipCapabilities
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsBarcodeSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsBitmapSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsLeft90RotationSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsRight90RotationSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) Is180RotationSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsPrintAreaSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::PosPrinterRuledLineCapabilities) RuledLineCapabilities() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::PointOfService::PosPrinterRotation>) SupportedBarcodeRotations() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::PointOfService::PosPrinterRotation>) SupportedBitmapRotations() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ICommonReceiptSlipCapabilities>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ICommonReceiptSlipCapabilities<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IJournalPrintJob
    {
        WINRT_IMPL_AUTO(void) Print(param::hstring const& data, winrt::Windows::Devices::PointOfService::PosPrinterPrintOptions const& printOptions) const;
        WINRT_IMPL_AUTO(void) FeedPaperByLine(int32_t lineCount) const;
        WINRT_IMPL_AUTO(void) FeedPaperByMapModeUnit(int32_t distance) const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IJournalPrintJob>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IJournalPrintJob<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IJournalPrinterCapabilities
    {
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IJournalPrinterCapabilities>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IJournalPrinterCapabilities<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IJournalPrinterCapabilities2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsReverseVideoSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsStrikethroughSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsSuperscriptSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsSubscriptSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsReversePaperFeedByLineSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsReversePaperFeedByMapModeUnitSupported() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IJournalPrinterCapabilities2>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IJournalPrinterCapabilities2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ILineDisplay
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayCapabilities) Capabilities() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) PhysicalDeviceName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) PhysicalDeviceDescription() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceControlDescription() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceControlVersion() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceServiceVersion() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::ClaimedLineDisplay>) ClaimAsync() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ILineDisplay>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplay<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ILineDisplay2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplayPowerStatus>) CheckPowerStatusAsync() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ILineDisplay2>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplay2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ILineDisplayAttributes
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsPowerNotifyEnabled() const;
        WINRT_IMPL_AUTO(void) IsPowerNotifyEnabled(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) Brightness() const;
        WINRT_IMPL_AUTO(void) Brightness(int32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) BlinkRate() const;
        WINRT_IMPL_AUTO(void) BlinkRate(winrt::Windows::Foundation::TimeSpan const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) ScreenSizeInCharacters() const;
        WINRT_IMPL_AUTO(void) ScreenSizeInCharacters(winrt::Windows::Foundation::Size const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) CharacterSet() const;
        WINRT_IMPL_AUTO(void) CharacterSet(int32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsCharacterSetMappingEnabled() const;
        WINRT_IMPL_AUTO(void) IsCharacterSetMappingEnabled(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayWindow) CurrentWindow() const;
        WINRT_IMPL_AUTO(void) CurrentWindow(winrt::Windows::Devices::PointOfService::LineDisplayWindow const& value) const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ILineDisplayAttributes>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplayAttributes<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ILineDisplayCapabilities
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsStatisticsReportingSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsStatisticsUpdatingSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::UnifiedPosPowerReportingType) PowerReportingType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) CanChangeScreenSize() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) CanDisplayBitmaps() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) CanReadCharacterAtCursor() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) CanMapCharacterSets() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) CanDisplayCustomGlyphs() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayTextAttributeGranularity) CanReverse() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayTextAttributeGranularity) CanBlink() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) CanChangeBlinkRate() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsBrightnessSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsCursorSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsHorizontalMarqueeSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsVerticalMarqueeSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsInterCharacterWaitSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) SupportedDescriptors() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) SupportedWindows() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ILineDisplayCapabilities>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplayCapabilities<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ILineDisplayCursor
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) CanCustomize() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsBlinkSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsBlockSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsHalfBlockSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsUnderlineSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsReverseSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsOtherSupported() const;
        WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayCursorAttributes) GetAttributes() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TryUpdateAttributesAsync(winrt::Windows::Devices::PointOfService::LineDisplayCursorAttributes const& attributes) const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ILineDisplayCursor>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplayCursor<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ILineDisplayCursorAttributes
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsBlinkEnabled() const;
        WINRT_IMPL_AUTO(void) IsBlinkEnabled(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayCursorType) CursorType() const;
        WINRT_IMPL_AUTO(void) CursorType(winrt::Windows::Devices::PointOfService::LineDisplayCursorType const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsAutoAdvanceEnabled() const;
        WINRT_IMPL_AUTO(void) IsAutoAdvanceEnabled(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Point) Position() const;
        WINRT_IMPL_AUTO(void) Position(winrt::Windows::Foundation::Point const& value) const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ILineDisplayCursorAttributes>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplayCursorAttributes<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ILineDisplayCustomGlyphs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) SizeInPixels() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<uint32_t>) SupportedGlyphCodes() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TryRedefineAsync(uint32_t glyphCode, winrt::Windows::Storage::Streams::IBuffer const& glyphData) const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ILineDisplayCustomGlyphs>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplayCustomGlyphs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ILineDisplayMarquee
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayMarqueeFormat) Format() const;
        WINRT_IMPL_AUTO(void) Format(winrt::Windows::Devices::PointOfService::LineDisplayMarqueeFormat const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) RepeatWaitInterval() const;
        WINRT_IMPL_AUTO(void) RepeatWaitInterval(winrt::Windows::Foundation::TimeSpan const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) ScrollWaitInterval() const;
        WINRT_IMPL_AUTO(void) ScrollWaitInterval(winrt::Windows::Foundation::TimeSpan const& value) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TryStartScrollingAsync(winrt::Windows::Devices::PointOfService::LineDisplayScrollDirection const& direction) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TryStopScrollingAsync() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ILineDisplayMarquee>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplayMarquee<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ILineDisplayStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplay>) FromIdAsync(param::hstring const& deviceId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::LineDisplay>) GetDefaultAsync() const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector() const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector(winrt::Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes) const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ILineDisplayStatics>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplayStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ILineDisplayStatics2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayStatisticsCategorySelector) StatisticsCategorySelector() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ILineDisplayStatics2>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplayStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ILineDisplayStatisticsCategorySelector
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) AllStatistics() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) UnifiedPosStatistics() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ManufacturerStatistics() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ILineDisplayStatisticsCategorySelector>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplayStatisticsCategorySelector<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ILineDisplayStatusUpdatedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayPowerStatus) Status() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ILineDisplayStatusUpdatedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplayStatusUpdatedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ILineDisplayStoredBitmap
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EscapeSequence() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TryDeleteAsync() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ILineDisplayStoredBitmap>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplayStoredBitmap<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ILineDisplayWindow
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) SizeInCharacters() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::TimeSpan) InterCharacterWaitInterval() const;
        WINRT_IMPL_AUTO(void) InterCharacterWaitInterval(winrt::Windows::Foundation::TimeSpan const& value) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TryRefreshAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TryDisplayTextAsync(param::hstring const& text, winrt::Windows::Devices::PointOfService::LineDisplayTextAttribute const& displayAttribute) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TryDisplayTextAsync(param::hstring const& text, winrt::Windows::Devices::PointOfService::LineDisplayTextAttribute const& displayAttribute, winrt::Windows::Foundation::Point const& startPosition) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TryDisplayTextAsync(param::hstring const& text) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TryScrollTextAsync(winrt::Windows::Devices::PointOfService::LineDisplayScrollDirection const& direction, uint32_t numberOfColumnsOrRows) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TryClearTextAsync() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ILineDisplayWindow>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplayWindow<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ILineDisplayWindow2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayCursor) Cursor() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::LineDisplayMarquee) Marquee() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<uint32_t>) ReadCharacterAtCursorAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TryDisplayStoredBitmapAtCursorAsync(winrt::Windows::Devices::PointOfService::LineDisplayStoredBitmap const& bitmap) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TryDisplayStorageFileBitmapAtCursorAsync(winrt::Windows::Storage::StorageFile const& bitmap) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TryDisplayStorageFileBitmapAtCursorAsync(winrt::Windows::Storage::StorageFile const& bitmap, winrt::Windows::Devices::PointOfService::LineDisplayHorizontalAlignment const& horizontalAlignment, winrt::Windows::Devices::PointOfService::LineDisplayVerticalAlignment const& verticalAlignment) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TryDisplayStorageFileBitmapAtCursorAsync(winrt::Windows::Storage::StorageFile const& bitmap, winrt::Windows::Devices::PointOfService::LineDisplayHorizontalAlignment const& horizontalAlignment, winrt::Windows::Devices::PointOfService::LineDisplayVerticalAlignment const& verticalAlignment, int32_t widthInPixels) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TryDisplayStorageFileBitmapAtPointAsync(winrt::Windows::Storage::StorageFile const& bitmap, winrt::Windows::Foundation::Point const& offsetInPixels) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TryDisplayStorageFileBitmapAtPointAsync(winrt::Windows::Storage::StorageFile const& bitmap, winrt::Windows::Foundation::Point const& offsetInPixels, int32_t widthInPixels) const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ILineDisplayWindow2>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ILineDisplayWindow2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IMagneticStripeReader
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderCapabilities) Capabilities() const;
        [[nodiscard]] WINRT_IMPL_AUTO(com_array<uint32_t>) SupportedCardTypes() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationProtocol) DeviceAuthenticationProtocol() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) CheckHealthAsync(winrt::Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const& level) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::ClaimedMagneticStripeReader>) ClaimReaderAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Storage::Streams::IBuffer>) RetrieveStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const;
        WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderErrorReportingType) GetErrorReportingType() const;
        WINRT_IMPL_AUTO(winrt::event_token) StatusUpdated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::MagneticStripeReader, winrt::Windows::Devices::PointOfService::MagneticStripeReaderStatusUpdatedEventArgs> const& handler) const;
        using StatusUpdated_revoker = impl::event_revoker<winrt::Windows::Devices::PointOfService::IMagneticStripeReader, &impl::abi_t<winrt::Windows::Devices::PointOfService::IMagneticStripeReader>::remove_StatusUpdated>;
        [[nodiscard]] StatusUpdated_revoker StatusUpdated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::MagneticStripeReader, winrt::Windows::Devices::PointOfService::MagneticStripeReaderStatusUpdatedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) StatusUpdated(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IMagneticStripeReader>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IMagneticStripeReader<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderReport) Report() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) LicenseNumber() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ExpirationDate() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Restrictions() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Class() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Endorsements() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) BirthDate() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) FirstName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Surname() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Suffix() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Gender() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) HairColor() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) EyeColor() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Height() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Weight() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Address() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) City() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) State() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) PostalCode() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderAamvaCardDataReceivedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IMagneticStripeReaderAamvaCardDataReceivedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IMagneticStripeReaderBankCardDataReceivedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderReport) Report() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) AccountNumber() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ExpirationDate() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) ServiceCode() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Title() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) FirstName() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) MiddleInitial() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Surname() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Suffix() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderBankCardDataReceivedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IMagneticStripeReaderBankCardDataReceivedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IMagneticStripeReaderCapabilities
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) CardAuthentication() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) SupportedEncryptionAlgorithms() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderAuthenticationLevel) AuthenticationLevel() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsIsoSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsJisOneSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsJisTwoSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::UnifiedPosPowerReportingType) PowerReportingType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsStatisticsReportingSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsStatisticsUpdatingSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsTrackDataMaskingSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsTransmitSentinelsSupported() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCapabilities>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IMagneticStripeReaderCapabilities<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IMagneticStripeReaderCardTypesStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Unknown() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Bank() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Aamva() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ExtendedBase() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderCardTypesStatics>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IMagneticStripeReaderCardTypesStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IMagneticStripeReaderEncryptionAlgorithmsStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) None() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) TripleDesDukpt() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ExtendedBase() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderEncryptionAlgorithmsStatics>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IMagneticStripeReaderEncryptionAlgorithmsStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IMagneticStripeReaderErrorOccurredEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType) Track1Status() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType) Track2Status() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType) Track3Status() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackErrorType) Track4Status() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::UnifiedPosErrorData) ErrorData() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderReport) PartialInputData() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderErrorOccurredEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IMagneticStripeReaderErrorOccurredEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IMagneticStripeReaderReport
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) CardType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackData) Track1() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackData) Track2() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackData) Track3() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderTrackData) Track4() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IMapView<hstring, hstring>) Properties() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) CardAuthenticationData() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) CardAuthenticationDataLength() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) AdditionalSecurityInformation() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderReport>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IMagneticStripeReaderReport<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IMagneticStripeReaderStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::MagneticStripeReader>) GetDefaultAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::MagneticStripeReader>) FromIdAsync(param::hstring const& deviceId) const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatics>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IMagneticStripeReaderStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IMagneticStripeReaderStatics2
    {
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector(winrt::Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes) const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatics2>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IMagneticStripeReaderStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IMagneticStripeReaderStatusUpdatedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderStatus) Status() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ExtendedStatus() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderStatusUpdatedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IMagneticStripeReaderStatusUpdatedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IMagneticStripeReaderTrackData
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) Data() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) DiscretionaryData() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Storage::Streams::IBuffer) EncryptedData() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderTrackData>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IMagneticStripeReaderTrackData<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::MagneticStripeReaderReport) Report() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IMagneticStripeReaderVendorSpecificCardDataReceivedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IPosPrinter
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DeviceId() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::PosPrinterCapabilities) Capabilities() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<uint32_t>) SupportedCharacterSets() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<hstring>) SupportedTypeFaces() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::PosPrinterStatus) Status() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::ClaimedPosPrinter>) ClaimPrinterAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) CheckHealthAsync(winrt::Windows::Devices::PointOfService::UnifiedPosHealthCheckLevel const& level) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<hstring>) GetStatisticsAsync(param::async_iterable<hstring> const& statisticsCategories) const;
        WINRT_IMPL_AUTO(winrt::event_token) StatusUpdated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::PosPrinter, winrt::Windows::Devices::PointOfService::PosPrinterStatusUpdatedEventArgs> const& handler) const;
        using StatusUpdated_revoker = impl::event_revoker<winrt::Windows::Devices::PointOfService::IPosPrinter, &impl::abi_t<winrt::Windows::Devices::PointOfService::IPosPrinter>::remove_StatusUpdated>;
        [[nodiscard]] StatusUpdated_revoker StatusUpdated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::Devices::PointOfService::PosPrinter, winrt::Windows::Devices::PointOfService::PosPrinterStatusUpdatedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) StatusUpdated(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IPosPrinter>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IPosPrinter<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IPosPrinter2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<uint32_t>) SupportedBarcodeSymbologies() const;
        WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::PosPrinterFontProperty) GetFontProperty(param::hstring const& typeface) const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IPosPrinter2>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IPosPrinter2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IPosPrinterCapabilities
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::UnifiedPosPowerReportingType) PowerReportingType() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsStatisticsReportingSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsStatisticsUpdatingSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) DefaultCharacterSet() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) HasCoverSensor() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) CanMapCharacterSet() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsTransactionSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::ReceiptPrinterCapabilities) Receipt() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::SlipPrinterCapabilities) Slip() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::JournalPrinterCapabilities) Journal() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IPosPrinterCapabilities>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IPosPrinterCapabilities<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IPosPrinterCharacterSetIdsStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Utf16LE() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Ascii() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) Ansi() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IPosPrinterCharacterSetIdsStatics>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IPosPrinterCharacterSetIdsStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IPosPrinterFontProperty
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) TypeFace() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsScalableToAnySize() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::Devices::PointOfService::SizeUInt32>) CharacterSizes() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IPosPrinterFontProperty>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IPosPrinterFontProperty<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IPosPrinterJob
    {
        WINRT_IMPL_AUTO(void) Print(param::hstring const& data) const;
        WINRT_IMPL_AUTO(void) PrintLine(param::hstring const& data) const;
        WINRT_IMPL_AUTO(void) PrintLine() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) ExecuteAsync() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IPosPrinterJob>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IPosPrinterJob<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) TypeFace() const;
        WINRT_IMPL_AUTO(void) TypeFace(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) CharacterHeight() const;
        WINRT_IMPL_AUTO(void) CharacterHeight(uint32_t value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) Bold() const;
        WINRT_IMPL_AUTO(void) Bold(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) Italic() const;
        WINRT_IMPL_AUTO(void) Italic(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) Underline() const;
        WINRT_IMPL_AUTO(void) Underline(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ReverseVideo() const;
        WINRT_IMPL_AUTO(void) ReverseVideo(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) Strikethrough() const;
        WINRT_IMPL_AUTO(void) Strikethrough(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) Superscript() const;
        WINRT_IMPL_AUTO(void) Superscript(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) Subscript() const;
        WINRT_IMPL_AUTO(void) Subscript(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) DoubleWide() const;
        WINRT_IMPL_AUTO(void) DoubleWide(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) DoubleHigh() const;
        WINRT_IMPL_AUTO(void) DoubleHigh(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::PosPrinterAlignment) Alignment() const;
        WINRT_IMPL_AUTO(void) Alignment(winrt::Windows::Devices::PointOfService::PosPrinterAlignment const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) CharacterSet() const;
        WINRT_IMPL_AUTO(void) CharacterSet(uint32_t value) const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IPosPrinterPrintOptions>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IPosPrinterPrintOptions<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IPosPrinterReleaseDeviceRequestedEventArgs
    {
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IPosPrinterReleaseDeviceRequestedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IPosPrinterReleaseDeviceRequestedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IPosPrinterStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::PosPrinter>) GetDefaultAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<winrt::Windows::Devices::PointOfService::PosPrinter>) FromIdAsync(param::hstring const& deviceId) const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IPosPrinterStatics>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IPosPrinterStatics<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IPosPrinterStatics2
    {
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector(winrt::Windows::Devices::PointOfService::PosConnectionTypes const& connectionTypes) const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IPosPrinterStatics2>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IPosPrinterStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IPosPrinterStatus
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::PosPrinterStatusKind) StatusKind() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ExtendedStatus() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IPosPrinterStatus>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IPosPrinterStatus<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IPosPrinterStatusUpdatedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::PosPrinterStatus) Status() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IPosPrinterStatusUpdatedEventArgs>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IPosPrinterStatusUpdatedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IReceiptOrSlipJob
    {
        WINRT_IMPL_AUTO(void) SetBarcodeRotation(winrt::Windows::Devices::PointOfService::PosPrinterRotation const& value) const;
        WINRT_IMPL_AUTO(void) SetPrintRotation(winrt::Windows::Devices::PointOfService::PosPrinterRotation const& value, bool includeBitmaps) const;
        WINRT_IMPL_AUTO(void) SetPrintArea(winrt::Windows::Foundation::Rect const& value) const;
        WINRT_IMPL_AUTO(void) SetBitmap(uint32_t bitmapNumber, winrt::Windows::Graphics::Imaging::BitmapFrame const& bitmap, winrt::Windows::Devices::PointOfService::PosPrinterAlignment const& alignment) const;
        WINRT_IMPL_AUTO(void) SetBitmap(uint32_t bitmapNumber, winrt::Windows::Graphics::Imaging::BitmapFrame const& bitmap, winrt::Windows::Devices::PointOfService::PosPrinterAlignment const& alignment, uint32_t width) const;
        WINRT_IMPL_AUTO(void) SetCustomAlignedBitmap(uint32_t bitmapNumber, winrt::Windows::Graphics::Imaging::BitmapFrame const& bitmap, uint32_t alignmentDistance) const;
        WINRT_IMPL_AUTO(void) SetCustomAlignedBitmap(uint32_t bitmapNumber, winrt::Windows::Graphics::Imaging::BitmapFrame const& bitmap, uint32_t alignmentDistance, uint32_t width) const;
        WINRT_IMPL_AUTO(void) PrintSavedBitmap(uint32_t bitmapNumber) const;
        WINRT_IMPL_AUTO(void) DrawRuledLine(param::hstring const& positionList, winrt::Windows::Devices::PointOfService::PosPrinterLineDirection const& lineDirection, uint32_t lineWidth, winrt::Windows::Devices::PointOfService::PosPrinterLineStyle const& lineStyle, uint32_t lineColor) const;
        WINRT_IMPL_AUTO(void) PrintBarcode(param::hstring const& data, uint32_t symbology, uint32_t height, uint32_t width, winrt::Windows::Devices::PointOfService::PosPrinterBarcodeTextPosition const& textPosition, winrt::Windows::Devices::PointOfService::PosPrinterAlignment const& alignment) const;
        WINRT_IMPL_AUTO(void) PrintBarcodeCustomAlign(param::hstring const& data, uint32_t symbology, uint32_t height, uint32_t width, winrt::Windows::Devices::PointOfService::PosPrinterBarcodeTextPosition const& textPosition, uint32_t alignmentDistance) const;
        WINRT_IMPL_AUTO(void) PrintBitmap(winrt::Windows::Graphics::Imaging::BitmapFrame const& bitmap, winrt::Windows::Devices::PointOfService::PosPrinterAlignment const& alignment) const;
        WINRT_IMPL_AUTO(void) PrintBitmap(winrt::Windows::Graphics::Imaging::BitmapFrame const& bitmap, winrt::Windows::Devices::PointOfService::PosPrinterAlignment const& alignment, uint32_t width) const;
        WINRT_IMPL_AUTO(void) PrintCustomAlignedBitmap(winrt::Windows::Graphics::Imaging::BitmapFrame const& bitmap, uint32_t alignmentDistance) const;
        WINRT_IMPL_AUTO(void) PrintCustomAlignedBitmap(winrt::Windows::Graphics::Imaging::BitmapFrame const& bitmap, uint32_t alignmentDistance, uint32_t width) const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IReceiptOrSlipJob>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IReceiptOrSlipJob<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IReceiptPrintJob
    {
        WINRT_IMPL_AUTO(void) MarkFeed(winrt::Windows::Devices::PointOfService::PosPrinterMarkFeedKind const& kind) const;
        WINRT_IMPL_AUTO(void) CutPaper(double percentage) const;
        WINRT_IMPL_AUTO(void) CutPaper() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IReceiptPrintJob>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IReceiptPrintJob<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IReceiptPrintJob2
    {
        WINRT_IMPL_AUTO(void) StampPaper() const;
        WINRT_IMPL_AUTO(void) Print(param::hstring const& data, winrt::Windows::Devices::PointOfService::PosPrinterPrintOptions const& printOptions) const;
        WINRT_IMPL_AUTO(void) FeedPaperByLine(int32_t lineCount) const;
        WINRT_IMPL_AUTO(void) FeedPaperByMapModeUnit(int32_t distance) const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IReceiptPrintJob2>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IReceiptPrintJob2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IReceiptPrinterCapabilities
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) CanCutPaper() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsStampSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::PosPrinterMarkFeedCapabilities) MarkFeedCapabilities() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IReceiptPrinterCapabilities<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IReceiptPrinterCapabilities2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsReverseVideoSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsStrikethroughSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsSuperscriptSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsSubscriptSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsReversePaperFeedByLineSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsReversePaperFeedByMapModeUnitSupported() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IReceiptPrinterCapabilities2>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IReceiptPrinterCapabilities2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ISlipPrintJob
    {
        WINRT_IMPL_AUTO(void) Print(param::hstring const& data, winrt::Windows::Devices::PointOfService::PosPrinterPrintOptions const& printOptions) const;
        WINRT_IMPL_AUTO(void) FeedPaperByLine(int32_t lineCount) const;
        WINRT_IMPL_AUTO(void) FeedPaperByMapModeUnit(int32_t distance) const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ISlipPrintJob>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ISlipPrintJob<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ISlipPrinterCapabilities
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsFullLengthSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsBothSidesPrintingSupported() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ISlipPrinterCapabilities>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ISlipPrinterCapabilities<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_ISlipPrinterCapabilities2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsReverseVideoSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsStrikethroughSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsSuperscriptSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsSubscriptSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsReversePaperFeedByLineSupported() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsReversePaperFeedByMapModeUnitSupported() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::ISlipPrinterCapabilities2>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_ISlipPrinterCapabilities2<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IUnifiedPosErrorData
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Message() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::UnifiedPosErrorSeverity) Severity() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::UnifiedPosErrorReason) Reason() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) ExtendedReason() const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IUnifiedPosErrorData>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IUnifiedPosErrorData<D>;
    };
    template <typename D>
    struct consume_Windows_Devices_PointOfService_IUnifiedPosErrorDataFactory
    {
        WINRT_IMPL_AUTO(winrt::Windows::Devices::PointOfService::UnifiedPosErrorData) CreateInstance(param::hstring const& message, winrt::Windows::Devices::PointOfService::UnifiedPosErrorSeverity const& severity, winrt::Windows::Devices::PointOfService::UnifiedPosErrorReason const& reason, uint32_t extendedReason) const;
    };
    template <> struct consume<winrt::Windows::Devices::PointOfService::IUnifiedPosErrorDataFactory>
    {
        template <typename D> using type = consume_Windows_Devices_PointOfService_IUnifiedPosErrorDataFactory<D>;
    };
    struct struct_Windows_Devices_PointOfService_SizeUInt32
    {
        uint32_t Width;
        uint32_t Height;
    };
    template <> struct abi<Windows::Devices::PointOfService::SizeUInt32>
    {
        using type = struct_Windows_Devices_PointOfService_SizeUInt32;
    };
}
#endif
