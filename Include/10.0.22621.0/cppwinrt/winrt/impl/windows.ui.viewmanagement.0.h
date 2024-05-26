// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_UI_ViewManagement_0_H
#define WINRT_Windows_UI_ViewManagement_0_H
WINRT_EXPORT namespace winrt::Windows::Devices::Enumeration
{
    struct DeviceInformation;
}
WINRT_EXPORT namespace winrt::Windows::Foundation
{
    template <typename T> struct __declspec(empty_bases) EventHandler;
    struct EventRegistrationToken;
    struct IAsyncAction;
    template <typename TResult> struct __declspec(empty_bases) IAsyncOperation;
    template <typename T> struct __declspec(empty_bases) IReference;
    struct Rect;
    struct Size;
    template <typename TSender, typename TResult> struct __declspec(empty_bases) TypedEventHandler;
}
WINRT_EXPORT namespace winrt::Windows::Foundation::Collections
{
    template <typename T> struct __declspec(empty_bases) IVectorView;
}
WINRT_EXPORT namespace winrt::Windows::UI
{
    struct Color;
    struct UIContext;
}
WINRT_EXPORT namespace winrt::Windows::UI::Core
{
    struct ICoreWindow;
}
WINRT_EXPORT namespace winrt::Windows::UI::Popups
{
    enum class Placement : int32_t;
}
WINRT_EXPORT namespace winrt::Windows::UI::WindowManagement
{
    struct DisplayRegion;
    struct WindowingEnvironment;
}
WINRT_EXPORT namespace winrt::Windows::UI::ViewManagement
{
    enum class ApplicationViewBoundsMode : int32_t
    {
        UseVisible = 0,
        UseCoreWindow = 1,
    };
    enum class ApplicationViewMode : int32_t
    {
        Default = 0,
        CompactOverlay = 1,
    };
    enum class ApplicationViewOrientation : int32_t
    {
        Landscape = 0,
        Portrait = 1,
    };
    enum class ApplicationViewState : int32_t
    {
        FullScreenLandscape = 0,
        Filled = 1,
        Snapped = 2,
        FullScreenPortrait = 3,
    };
    enum class ApplicationViewSwitchingOptions : uint32_t
    {
        Default = 0,
        SkipAnimation = 0x1,
        ConsolidateViews = 0x2,
    };
    enum class ApplicationViewWindowingMode : int32_t
    {
        Auto = 0,
        PreferredLaunchViewSize = 1,
        FullScreen = 2,
        CompactOverlay = 3,
        Maximized = 4,
    };
    enum class FullScreenSystemOverlayMode : int32_t
    {
        Standard = 0,
        Minimal = 1,
    };
    enum class HandPreference : int32_t
    {
        LeftHanded = 0,
        RightHanded = 1,
    };
    enum class ScreenCaptureDisabledBehavior : int32_t
    {
        DrawAsBlack = 0,
        ExcludeFromCapture = 1,
    };
    enum class UIColorType : int32_t
    {
        Background = 0,
        Foreground = 1,
        AccentDark3 = 2,
        AccentDark2 = 3,
        AccentDark1 = 4,
        Accent = 5,
        AccentLight1 = 6,
        AccentLight2 = 7,
        AccentLight3 = 8,
        Complement = 9,
    };
    enum class UIElementType : int32_t
    {
        ActiveCaption = 0,
        Background = 1,
        ButtonFace = 2,
        ButtonText = 3,
        CaptionText = 4,
        GrayText = 5,
        Highlight = 6,
        HighlightText = 7,
        Hotlight = 8,
        InactiveCaption = 9,
        InactiveCaptionText = 10,
        Window = 11,
        WindowText = 12,
        AccentColor = 1000,
        TextHigh = 1001,
        TextMedium = 1002,
        TextLow = 1003,
        TextContrastWithHigh = 1004,
        NonTextHigh = 1005,
        NonTextMediumHigh = 1006,
        NonTextMedium = 1007,
        NonTextMediumLow = 1008,
        NonTextLow = 1009,
        PageBackground = 1010,
        PopupBackground = 1011,
        OverlayOutsidePopup = 1012,
    };
    enum class UserInteractionMode : int32_t
    {
        Mouse = 0,
        Touch = 1,
    };
    enum class ViewSizePreference : int32_t
    {
        Default = 0,
        UseLess = 1,
        UseHalf = 2,
        UseMore = 3,
        UseMinimum = 4,
        UseNone = 5,
        Custom = 6,
    };
    struct IAccessibilitySettings;
    struct IActivationViewSwitcher;
    struct IApplicationView;
    struct IApplicationView2;
    struct IApplicationView3;
    struct IApplicationView4;
    struct IApplicationView7;
    struct IApplicationView9;
    struct IApplicationViewConsolidatedEventArgs;
    struct IApplicationViewConsolidatedEventArgs2;
    struct IApplicationViewFullscreenStatics;
    struct IApplicationViewInteropStatics;
    struct IApplicationViewScaling;
    struct IApplicationViewScalingStatics;
    struct IApplicationViewStatics;
    struct IApplicationViewStatics2;
    struct IApplicationViewStatics3;
    struct IApplicationViewStatics4;
    struct IApplicationViewSwitcherStatics;
    struct IApplicationViewSwitcherStatics2;
    struct IApplicationViewSwitcherStatics3;
    struct IApplicationViewTitleBar;
    struct IApplicationViewTransferContext;
    struct IApplicationViewTransferContextStatics;
    struct IApplicationViewWithContext;
    struct IInputPane;
    struct IInputPane2;
    struct IInputPaneControl;
    struct IInputPaneStatics;
    struct IInputPaneStatics2;
    struct IInputPaneVisibilityEventArgs;
    struct IProjectionManagerStatics;
    struct IProjectionManagerStatics2;
    struct IStatusBar;
    struct IStatusBarProgressIndicator;
    struct IStatusBarStatics;
    struct IUISettings;
    struct IUISettings2;
    struct IUISettings3;
    struct IUISettings4;
    struct IUISettings5;
    struct IUISettings6;
    struct IUISettingsAnimationsEnabledChangedEventArgs;
    struct IUISettingsAutoHideScrollBarsChangedEventArgs;
    struct IUISettingsMessageDurationChangedEventArgs;
    struct IUIViewSettings;
    struct IUIViewSettingsStatics;
    struct IViewModePreferences;
    struct IViewModePreferencesStatics;
    struct AccessibilitySettings;
    struct ActivationViewSwitcher;
    struct ApplicationView;
    struct ApplicationViewConsolidatedEventArgs;
    struct ApplicationViewScaling;
    struct ApplicationViewSwitcher;
    struct ApplicationViewTitleBar;
    struct ApplicationViewTransferContext;
    struct InputPane;
    struct InputPaneVisibilityEventArgs;
    struct ProjectionManager;
    struct StatusBar;
    struct StatusBarProgressIndicator;
    struct UISettings;
    struct UISettingsAnimationsEnabledChangedEventArgs;
    struct UISettingsAutoHideScrollBarsChangedEventArgs;
    struct UISettingsMessageDurationChangedEventArgs;
    struct UIViewSettings;
    struct ViewModePreferences;
}
namespace winrt::impl
{
    template <> struct category<winrt::Windows::UI::ViewManagement::IAccessibilitySettings>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IActivationViewSwitcher>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IApplicationView>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IApplicationView2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IApplicationView3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IApplicationView4>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IApplicationView7>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IApplicationView9>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IApplicationViewFullscreenStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IApplicationViewInteropStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IApplicationViewScaling>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IApplicationViewScalingStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IApplicationViewStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IApplicationViewStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IApplicationViewStatics3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IApplicationViewStatics4>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IApplicationViewSwitcherStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IApplicationViewSwitcherStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IApplicationViewSwitcherStatics3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IApplicationViewTitleBar>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IApplicationViewTransferContext>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IApplicationViewTransferContextStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IApplicationViewWithContext>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IInputPane>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IInputPane2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IInputPaneControl>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IInputPaneStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IInputPaneStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IInputPaneVisibilityEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IProjectionManagerStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IProjectionManagerStatics2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IStatusBar>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IStatusBarProgressIndicator>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IStatusBarStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IUISettings>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IUISettings2>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IUISettings3>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IUISettings4>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IUISettings5>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IUISettings6>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IUISettingsAnimationsEnabledChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IUISettingsAutoHideScrollBarsChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IUISettingsMessageDurationChangedEventArgs>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IUIViewSettings>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IUIViewSettingsStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IViewModePreferences>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::IViewModePreferencesStatics>{ using type = interface_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::AccessibilitySettings>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::ActivationViewSwitcher>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::ApplicationView>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::ApplicationViewConsolidatedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::ApplicationViewScaling>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::ApplicationViewSwitcher>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::ApplicationViewTitleBar>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::ApplicationViewTransferContext>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::InputPane>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::InputPaneVisibilityEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::ProjectionManager>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::StatusBar>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::StatusBarProgressIndicator>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::UISettings>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::UISettingsAnimationsEnabledChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::UISettingsAutoHideScrollBarsChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::UISettingsMessageDurationChangedEventArgs>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::UIViewSettings>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::ViewModePreferences>{ using type = class_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::ApplicationViewBoundsMode>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::ApplicationViewMode>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::ApplicationViewOrientation>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::ApplicationViewState>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::ApplicationViewSwitchingOptions>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::ApplicationViewWindowingMode>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::FullScreenSystemOverlayMode>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::HandPreference>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::ScreenCaptureDisabledBehavior>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::UIColorType>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::UIElementType>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::UserInteractionMode>{ using type = enum_category; };
    template <> struct category<winrt::Windows::UI::ViewManagement::ViewSizePreference>{ using type = enum_category; };
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::AccessibilitySettings> = L"Windows.UI.ViewManagement.AccessibilitySettings";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::ActivationViewSwitcher> = L"Windows.UI.ViewManagement.ActivationViewSwitcher";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::ApplicationView> = L"Windows.UI.ViewManagement.ApplicationView";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::ApplicationViewConsolidatedEventArgs> = L"Windows.UI.ViewManagement.ApplicationViewConsolidatedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::ApplicationViewScaling> = L"Windows.UI.ViewManagement.ApplicationViewScaling";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::ApplicationViewSwitcher> = L"Windows.UI.ViewManagement.ApplicationViewSwitcher";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::ApplicationViewTitleBar> = L"Windows.UI.ViewManagement.ApplicationViewTitleBar";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::ApplicationViewTransferContext> = L"Windows.UI.ViewManagement.ApplicationViewTransferContext";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::InputPane> = L"Windows.UI.ViewManagement.InputPane";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::InputPaneVisibilityEventArgs> = L"Windows.UI.ViewManagement.InputPaneVisibilityEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::ProjectionManager> = L"Windows.UI.ViewManagement.ProjectionManager";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::StatusBar> = L"Windows.UI.ViewManagement.StatusBar";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::StatusBarProgressIndicator> = L"Windows.UI.ViewManagement.StatusBarProgressIndicator";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::UISettings> = L"Windows.UI.ViewManagement.UISettings";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::UISettingsAnimationsEnabledChangedEventArgs> = L"Windows.UI.ViewManagement.UISettingsAnimationsEnabledChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::UISettingsAutoHideScrollBarsChangedEventArgs> = L"Windows.UI.ViewManagement.UISettingsAutoHideScrollBarsChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::UISettingsMessageDurationChangedEventArgs> = L"Windows.UI.ViewManagement.UISettingsMessageDurationChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::UIViewSettings> = L"Windows.UI.ViewManagement.UIViewSettings";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::ViewModePreferences> = L"Windows.UI.ViewManagement.ViewModePreferences";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::ApplicationViewBoundsMode> = L"Windows.UI.ViewManagement.ApplicationViewBoundsMode";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::ApplicationViewMode> = L"Windows.UI.ViewManagement.ApplicationViewMode";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::ApplicationViewOrientation> = L"Windows.UI.ViewManagement.ApplicationViewOrientation";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::ApplicationViewState> = L"Windows.UI.ViewManagement.ApplicationViewState";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::ApplicationViewSwitchingOptions> = L"Windows.UI.ViewManagement.ApplicationViewSwitchingOptions";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::ApplicationViewWindowingMode> = L"Windows.UI.ViewManagement.ApplicationViewWindowingMode";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::FullScreenSystemOverlayMode> = L"Windows.UI.ViewManagement.FullScreenSystemOverlayMode";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::HandPreference> = L"Windows.UI.ViewManagement.HandPreference";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::ScreenCaptureDisabledBehavior> = L"Windows.UI.ViewManagement.ScreenCaptureDisabledBehavior";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::UIColorType> = L"Windows.UI.ViewManagement.UIColorType";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::UIElementType> = L"Windows.UI.ViewManagement.UIElementType";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::UserInteractionMode> = L"Windows.UI.ViewManagement.UserInteractionMode";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::ViewSizePreference> = L"Windows.UI.ViewManagement.ViewSizePreference";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IAccessibilitySettings> = L"Windows.UI.ViewManagement.IAccessibilitySettings";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IActivationViewSwitcher> = L"Windows.UI.ViewManagement.IActivationViewSwitcher";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IApplicationView> = L"Windows.UI.ViewManagement.IApplicationView";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IApplicationView2> = L"Windows.UI.ViewManagement.IApplicationView2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IApplicationView3> = L"Windows.UI.ViewManagement.IApplicationView3";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IApplicationView4> = L"Windows.UI.ViewManagement.IApplicationView4";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IApplicationView7> = L"Windows.UI.ViewManagement.IApplicationView7";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IApplicationView9> = L"Windows.UI.ViewManagement.IApplicationView9";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs> = L"Windows.UI.ViewManagement.IApplicationViewConsolidatedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs2> = L"Windows.UI.ViewManagement.IApplicationViewConsolidatedEventArgs2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IApplicationViewFullscreenStatics> = L"Windows.UI.ViewManagement.IApplicationViewFullscreenStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IApplicationViewInteropStatics> = L"Windows.UI.ViewManagement.IApplicationViewInteropStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IApplicationViewScaling> = L"Windows.UI.ViewManagement.IApplicationViewScaling";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IApplicationViewScalingStatics> = L"Windows.UI.ViewManagement.IApplicationViewScalingStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IApplicationViewStatics> = L"Windows.UI.ViewManagement.IApplicationViewStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IApplicationViewStatics2> = L"Windows.UI.ViewManagement.IApplicationViewStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IApplicationViewStatics3> = L"Windows.UI.ViewManagement.IApplicationViewStatics3";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IApplicationViewStatics4> = L"Windows.UI.ViewManagement.IApplicationViewStatics4";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IApplicationViewSwitcherStatics> = L"Windows.UI.ViewManagement.IApplicationViewSwitcherStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IApplicationViewSwitcherStatics2> = L"Windows.UI.ViewManagement.IApplicationViewSwitcherStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IApplicationViewSwitcherStatics3> = L"Windows.UI.ViewManagement.IApplicationViewSwitcherStatics3";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IApplicationViewTitleBar> = L"Windows.UI.ViewManagement.IApplicationViewTitleBar";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IApplicationViewTransferContext> = L"Windows.UI.ViewManagement.IApplicationViewTransferContext";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IApplicationViewTransferContextStatics> = L"Windows.UI.ViewManagement.IApplicationViewTransferContextStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IApplicationViewWithContext> = L"Windows.UI.ViewManagement.IApplicationViewWithContext";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IInputPane> = L"Windows.UI.ViewManagement.IInputPane";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IInputPane2> = L"Windows.UI.ViewManagement.IInputPane2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IInputPaneControl> = L"Windows.UI.ViewManagement.IInputPaneControl";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IInputPaneStatics> = L"Windows.UI.ViewManagement.IInputPaneStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IInputPaneStatics2> = L"Windows.UI.ViewManagement.IInputPaneStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IInputPaneVisibilityEventArgs> = L"Windows.UI.ViewManagement.IInputPaneVisibilityEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IProjectionManagerStatics> = L"Windows.UI.ViewManagement.IProjectionManagerStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IProjectionManagerStatics2> = L"Windows.UI.ViewManagement.IProjectionManagerStatics2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IStatusBar> = L"Windows.UI.ViewManagement.IStatusBar";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IStatusBarProgressIndicator> = L"Windows.UI.ViewManagement.IStatusBarProgressIndicator";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IStatusBarStatics> = L"Windows.UI.ViewManagement.IStatusBarStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IUISettings> = L"Windows.UI.ViewManagement.IUISettings";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IUISettings2> = L"Windows.UI.ViewManagement.IUISettings2";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IUISettings3> = L"Windows.UI.ViewManagement.IUISettings3";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IUISettings4> = L"Windows.UI.ViewManagement.IUISettings4";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IUISettings5> = L"Windows.UI.ViewManagement.IUISettings5";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IUISettings6> = L"Windows.UI.ViewManagement.IUISettings6";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IUISettingsAnimationsEnabledChangedEventArgs> = L"Windows.UI.ViewManagement.IUISettingsAnimationsEnabledChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IUISettingsAutoHideScrollBarsChangedEventArgs> = L"Windows.UI.ViewManagement.IUISettingsAutoHideScrollBarsChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IUISettingsMessageDurationChangedEventArgs> = L"Windows.UI.ViewManagement.IUISettingsMessageDurationChangedEventArgs";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IUIViewSettings> = L"Windows.UI.ViewManagement.IUIViewSettings";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IUIViewSettingsStatics> = L"Windows.UI.ViewManagement.IUIViewSettingsStatics";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IViewModePreferences> = L"Windows.UI.ViewManagement.IViewModePreferences";
    template <> inline constexpr auto& name_v<winrt::Windows::UI::ViewManagement::IViewModePreferencesStatics> = L"Windows.UI.ViewManagement.IViewModePreferencesStatics";
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IAccessibilitySettings>{ 0xFE0E8147,0xC4C0,0x4562,{ 0xB9,0x62,0x13,0x27,0xB5,0x2A,0xD5,0xB9 } }; // FE0E8147-C4C0-4562-B962-1327B52AD5B9
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IActivationViewSwitcher>{ 0xDCA71BB6,0x7350,0x492B,{ 0xAA,0xC7,0xC8,0xA1,0x3D,0x72,0x24,0xAD } }; // DCA71BB6-7350-492B-AAC7-C8A13D7224AD
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IApplicationView>{ 0xD222D519,0x4361,0x451E,{ 0x96,0xC4,0x60,0xF4,0xF9,0x74,0x2D,0xB0 } }; // D222D519-4361-451E-96C4-60F4F9742DB0
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IApplicationView2>{ 0xE876B196,0xA545,0x40DC,{ 0xB5,0x94,0x45,0x0C,0xBA,0x68,0xCC,0x00 } }; // E876B196-A545-40DC-B594-450CBA68CC00
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IApplicationView3>{ 0x903C9CE5,0x793A,0x4FDF,{ 0xA2,0xB2,0xAF,0x1A,0xC2,0x1E,0x31,0x08 } }; // 903C9CE5-793A-4FDF-A2B2-AF1AC21E3108
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IApplicationView4>{ 0x15E5CBEC,0x9E0F,0x46B5,{ 0xBC,0x3F,0x9B,0xF6,0x53,0xE7,0x4B,0x5E } }; // 15E5CBEC-9E0F-46B5-BC3F-9BF653E74B5E
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IApplicationView7>{ 0xA0369647,0x5FAF,0x5AA6,{ 0x9C,0x38,0xBE,0xFB,0xB1,0x2A,0x07,0x1E } }; // A0369647-5FAF-5AA6-9C38-BEFBB12A071E
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IApplicationView9>{ 0x9C6516F9,0x021A,0x5F01,{ 0x93,0xE5,0x9B,0xDA,0xD2,0x64,0x75,0x74 } }; // 9C6516F9-021A-5F01-93E5-9BDAD2647574
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs>{ 0x514449EC,0x7EA2,0x4DE7,{ 0xA6,0xA6,0x7D,0xFB,0xAA,0xEB,0xB6,0xFB } }; // 514449EC-7EA2-4DE7-A6A6-7DFBAAEBB6FB
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs2>{ 0x1C199ECC,0x6DC1,0x40F4,{ 0xAF,0xEE,0x07,0xD9,0xEA,0x29,0x64,0x30 } }; // 1C199ECC-6DC1-40F4-AFEE-07D9EA296430
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IApplicationViewFullscreenStatics>{ 0xBC792EBD,0x64FE,0x4B65,{ 0xA0,0xC0,0x90,0x1C,0xE2,0xB6,0x86,0x36 } }; // BC792EBD-64FE-4B65-A0C0-901CE2B68636
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IApplicationViewInteropStatics>{ 0xC446FB5D,0x4793,0x4896,{ 0xA8,0xE2,0xBE,0x57,0xA8,0xBB,0x0F,0x50 } }; // C446FB5D-4793-4896-A8E2-BE57A8BB0F50
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IApplicationViewScaling>{ 0x1D0DDC23,0x23F3,0x4B2D,{ 0x84,0xFE,0x74,0xBF,0x37,0xB4,0x8B,0x66 } }; // 1D0DDC23-23F3-4B2D-84FE-74BF37B48B66
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IApplicationViewScalingStatics>{ 0xB08FECF0,0xB946,0x45C8,{ 0xA5,0xE3,0x71,0xF5,0xAA,0x78,0xF8,0x61 } }; // B08FECF0-B946-45C8-A5E3-71F5AA78F861
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IApplicationViewStatics>{ 0x010A6306,0xC433,0x44E5,{ 0xA9,0xF2,0xBD,0x84,0xD4,0x03,0x0A,0x95 } }; // 010A6306-C433-44E5-A9F2-BD84D4030A95
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IApplicationViewStatics2>{ 0xAF338AE5,0xCF64,0x423C,{ 0x85,0xE5,0xF3,0xE7,0x24,0x48,0xFB,0x23 } }; // AF338AE5-CF64-423C-85E5-F3E72448FB23
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IApplicationViewStatics3>{ 0xA28D7594,0x8C41,0x4E13,{ 0x97,0x19,0x51,0x64,0x79,0x6F,0xE4,0xC7 } }; // A28D7594-8C41-4E13-9719-5164796FE4C7
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IApplicationViewStatics4>{ 0x08FD8D33,0x2611,0x5336,{ 0xA3,0x15,0xD9,0x8E,0x63,0x66,0xC9,0xDB } }; // 08FD8D33-2611-5336-A315-D98E6366C9DB
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IApplicationViewSwitcherStatics>{ 0x975F2F1E,0xE656,0x4C5E,{ 0xA0,0xA1,0x71,0x7C,0x6F,0xFA,0x7D,0x64 } }; // 975F2F1E-E656-4C5E-A0A1-717C6FFA7D64
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IApplicationViewSwitcherStatics2>{ 0x60E995CD,0x4FC2,0x48C4,{ 0xB8,0xE3,0x39,0x5F,0x2B,0x9F,0x0F,0xC1 } }; // 60E995CD-4FC2-48C4-B8E3-395F2B9F0FC1
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IApplicationViewSwitcherStatics3>{ 0x92059420,0x80A7,0x486D,{ 0xB2,0x1F,0xC7,0xA4,0xA2,0x42,0xA3,0x83 } }; // 92059420-80A7-486D-B21F-C7A4A242A383
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IApplicationViewTitleBar>{ 0x00924AC0,0x932B,0x4A6B,{ 0x9C,0x4B,0xDC,0x38,0xC8,0x24,0x78,0xCE } }; // 00924AC0-932B-4A6B-9C4B-DC38C82478CE
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IApplicationViewTransferContext>{ 0x8574BC63,0x3C17,0x408E,{ 0x94,0x08,0x8A,0x1A,0x9E,0xA8,0x1B,0xFA } }; // 8574BC63-3C17-408E-9408-8A1A9EA81BFA
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IApplicationViewTransferContextStatics>{ 0x15A89D92,0xDD79,0x4B0B,{ 0xBC,0x47,0xD5,0xF1,0x95,0xF1,0x46,0x61 } }; // 15A89D92-DD79-4B0B-BC47-D5F195F14661
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IApplicationViewWithContext>{ 0xBD55D512,0x9DC1,0x44FC,{ 0x85,0x01,0x66,0x66,0x25,0xDF,0x60,0xDC } }; // BD55D512-9DC1-44FC-8501-666625DF60DC
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IInputPane>{ 0x640ADA70,0x06F3,0x4C87,{ 0xA6,0x78,0x98,0x29,0xC9,0x12,0x7C,0x28 } }; // 640ADA70-06F3-4C87-A678-9829C9127C28
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IInputPane2>{ 0x8A6B3F26,0x7090,0x4793,{ 0x94,0x4C,0xC3,0xF2,0xCD,0xE2,0x62,0x76 } }; // 8A6B3F26-7090-4793-944C-C3F2CDE26276
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IInputPaneControl>{ 0x088BB24F,0x962F,0x489D,{ 0xAA,0x6E,0xC6,0xBE,0x1A,0x0A,0x6E,0x52 } }; // 088BB24F-962F-489D-AA6E-C6BE1A0A6E52
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IInputPaneStatics>{ 0x95F4AF3A,0xEF47,0x424A,{ 0x97,0x41,0xFD,0x28,0x15,0xEB,0xA2,0xBD } }; // 95F4AF3A-EF47-424A-9741-FD2815EBA2BD
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IInputPaneStatics2>{ 0x1B63529B,0xD9EC,0x4531,{ 0x84,0x45,0x71,0xBA,0xB9,0xFB,0x82,0x8E } }; // 1B63529B-D9EC-4531-8445-71BAB9FB828E
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IInputPaneVisibilityEventArgs>{ 0xD243E016,0xD907,0x4FCC,{ 0xBB,0x8D,0xF7,0x7B,0xAA,0x50,0x28,0xF1 } }; // D243E016-D907-4FCC-BB8D-F77BAA5028F1
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IProjectionManagerStatics>{ 0xB65F913D,0xE2F0,0x4FFD,{ 0xBA,0x95,0x34,0x24,0x16,0x47,0xE4,0x5C } }; // B65F913D-E2F0-4FFD-BA95-34241647E45C
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IProjectionManagerStatics2>{ 0xF33D2F43,0x2749,0x4CDE,{ 0xB9,0x77,0xC0,0xC4,0x1E,0x74,0x15,0xD1 } }; // F33D2F43-2749-4CDE-B977-C0C41E7415D1
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IStatusBar>{ 0x0FFCC5BF,0x98D0,0x4864,{ 0xB1,0xE8,0xB3,0xF4,0x02,0x0B,0xE8,0xB4 } }; // 0FFCC5BF-98D0-4864-B1E8-B3F4020BE8B4
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IStatusBarProgressIndicator>{ 0x76CB2670,0xA3D7,0x49CF,{ 0x82,0x00,0x4F,0x3E,0xED,0xCA,0x27,0xBB } }; // 76CB2670-A3D7-49CF-8200-4F3EEDCA27BB
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IStatusBarStatics>{ 0x8B463FDF,0x422F,0x4561,{ 0x88,0x06,0xFB,0x12,0x89,0xCA,0xDF,0xB7 } }; // 8B463FDF-422F-4561-8806-FB1289CADFB7
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IUISettings>{ 0x85361600,0x1C63,0x4627,{ 0xBC,0xB1,0x3A,0x89,0xE0,0xBC,0x9C,0x55 } }; // 85361600-1C63-4627-BCB1-3A89E0BC9C55
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IUISettings2>{ 0xBAD82401,0x2721,0x44F9,{ 0xBB,0x91,0x2B,0xB2,0x28,0xBE,0x44,0x2F } }; // BAD82401-2721-44F9-BB91-2BB228BE442F
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IUISettings3>{ 0x03021BE4,0x5254,0x4781,{ 0x81,0x94,0x51,0x68,0xF7,0xD0,0x6D,0x7B } }; // 03021BE4-5254-4781-8194-5168F7D06D7B
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IUISettings4>{ 0x52BB3002,0x919B,0x4D6B,{ 0x9B,0x78,0x8D,0xD6,0x6F,0xF4,0xB9,0x3B } }; // 52BB3002-919B-4D6B-9B78-8DD66FF4B93B
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IUISettings5>{ 0x5349D588,0x0CB5,0x5F05,{ 0xBD,0x34,0x70,0x6B,0x32,0x31,0xF0,0xBD } }; // 5349D588-0CB5-5F05-BD34-706B3231F0BD
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IUISettings6>{ 0xAEF19BD7,0xFE31,0x5A04,{ 0xAD,0xA4,0x46,0x9A,0xAE,0xC6,0xDF,0xA9 } }; // AEF19BD7-FE31-5A04-ADA4-469AAEC6DFA9
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IUISettingsAnimationsEnabledChangedEventArgs>{ 0x0C7B4B3D,0x2EA1,0x533E,{ 0x89,0x4D,0x41,0x5B,0xC5,0x24,0x3C,0x29 } }; // 0C7B4B3D-2EA1-533E-894D-415BC5243C29
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IUISettingsAutoHideScrollBarsChangedEventArgs>{ 0x87AFD4B2,0x9146,0x5F02,{ 0x8F,0x6B,0x06,0xD4,0x54,0x17,0x4C,0x0F } }; // 87AFD4B2-9146-5F02-8F6B-06D454174C0F
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IUISettingsMessageDurationChangedEventArgs>{ 0x338AAD52,0x4A5D,0x5B59,{ 0x80,0x02,0xD9,0x30,0xF6,0x08,0xFD,0x6E } }; // 338AAD52-4A5D-5B59-8002-D930F608FD6E
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IUIViewSettings>{ 0xC63657F6,0x8850,0x470D,{ 0x88,0xF8,0x45,0x5E,0x16,0xEA,0x2C,0x26 } }; // C63657F6-8850-470D-88F8-455E16EA2C26
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IUIViewSettingsStatics>{ 0x595C97A5,0xF8F6,0x41CF,{ 0xB0,0xFB,0xAA,0xCD,0xB8,0x1F,0xD5,0xF6 } }; // 595C97A5-F8F6-41CF-B0FB-AACDB81FD5F6
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IViewModePreferences>{ 0x878FCD3A,0x0B99,0x42C9,{ 0x84,0xD0,0xD3,0xF1,0xD4,0x03,0x55,0x4B } }; // 878FCD3A-0B99-42C9-84D0-D3F1D403554B
    template <> inline constexpr guid guid_v<winrt::Windows::UI::ViewManagement::IViewModePreferencesStatics>{ 0x69B60A65,0x5DE5,0x40D8,{ 0x83,0x06,0x38,0x33,0xDF,0x7A,0x22,0x74 } }; // 69B60A65-5DE5-40D8-8306-3833DF7A2274
    template <> struct default_interface<winrt::Windows::UI::ViewManagement::AccessibilitySettings>{ using type = winrt::Windows::UI::ViewManagement::IAccessibilitySettings; };
    template <> struct default_interface<winrt::Windows::UI::ViewManagement::ActivationViewSwitcher>{ using type = winrt::Windows::UI::ViewManagement::IActivationViewSwitcher; };
    template <> struct default_interface<winrt::Windows::UI::ViewManagement::ApplicationView>{ using type = winrt::Windows::UI::ViewManagement::IApplicationView; };
    template <> struct default_interface<winrt::Windows::UI::ViewManagement::ApplicationViewConsolidatedEventArgs>{ using type = winrt::Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::ViewManagement::ApplicationViewScaling>{ using type = winrt::Windows::UI::ViewManagement::IApplicationViewScaling; };
    template <> struct default_interface<winrt::Windows::UI::ViewManagement::ApplicationViewTitleBar>{ using type = winrt::Windows::UI::ViewManagement::IApplicationViewTitleBar; };
    template <> struct default_interface<winrt::Windows::UI::ViewManagement::ApplicationViewTransferContext>{ using type = winrt::Windows::UI::ViewManagement::IApplicationViewTransferContext; };
    template <> struct default_interface<winrt::Windows::UI::ViewManagement::InputPane>{ using type = winrt::Windows::UI::ViewManagement::IInputPane; };
    template <> struct default_interface<winrt::Windows::UI::ViewManagement::InputPaneVisibilityEventArgs>{ using type = winrt::Windows::UI::ViewManagement::IInputPaneVisibilityEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::ViewManagement::StatusBar>{ using type = winrt::Windows::UI::ViewManagement::IStatusBar; };
    template <> struct default_interface<winrt::Windows::UI::ViewManagement::StatusBarProgressIndicator>{ using type = winrt::Windows::UI::ViewManagement::IStatusBarProgressIndicator; };
    template <> struct default_interface<winrt::Windows::UI::ViewManagement::UISettings>{ using type = winrt::Windows::UI::ViewManagement::IUISettings; };
    template <> struct default_interface<winrt::Windows::UI::ViewManagement::UISettingsAnimationsEnabledChangedEventArgs>{ using type = winrt::Windows::UI::ViewManagement::IUISettingsAnimationsEnabledChangedEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::ViewManagement::UISettingsAutoHideScrollBarsChangedEventArgs>{ using type = winrt::Windows::UI::ViewManagement::IUISettingsAutoHideScrollBarsChangedEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::ViewManagement::UISettingsMessageDurationChangedEventArgs>{ using type = winrt::Windows::UI::ViewManagement::IUISettingsMessageDurationChangedEventArgs; };
    template <> struct default_interface<winrt::Windows::UI::ViewManagement::UIViewSettings>{ using type = winrt::Windows::UI::ViewManagement::IUIViewSettings; };
    template <> struct default_interface<winrt::Windows::UI::ViewManagement::ViewModePreferences>{ using type = winrt::Windows::UI::ViewManagement::IViewModePreferences; };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IAccessibilitySettings>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_HighContrast(bool*) noexcept = 0;
            virtual int32_t __stdcall get_HighContrastScheme(void**) noexcept = 0;
            virtual int32_t __stdcall add_HighContrastChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_HighContrastChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IActivationViewSwitcher>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ShowAsStandaloneAsync(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall ShowAsStandaloneWithSizePreferenceAsync(int32_t, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall IsViewPresentedOnActivationVirtualDesktop(int32_t, bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IApplicationView>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Orientation(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_AdjacentToLeftDisplayEdge(bool*) noexcept = 0;
            virtual int32_t __stdcall get_AdjacentToRightDisplayEdge(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsFullScreen(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsOnLockScreen(bool*) noexcept = 0;
            virtual int32_t __stdcall get_IsScreenCaptureEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall put_IsScreenCaptureEnabled(bool) noexcept = 0;
            virtual int32_t __stdcall put_Title(void*) noexcept = 0;
            virtual int32_t __stdcall get_Title(void**) noexcept = 0;
            virtual int32_t __stdcall get_Id(int32_t*) noexcept = 0;
            virtual int32_t __stdcall add_Consolidated(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Consolidated(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IApplicationView2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_SuppressSystemOverlays(bool*) noexcept = 0;
            virtual int32_t __stdcall put_SuppressSystemOverlays(bool) noexcept = 0;
            virtual int32_t __stdcall get_VisibleBounds(winrt::Windows::Foundation::Rect*) noexcept = 0;
            virtual int32_t __stdcall add_VisibleBoundsChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_VisibleBoundsChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall SetDesiredBoundsMode(int32_t, bool*) noexcept = 0;
            virtual int32_t __stdcall get_DesiredBoundsMode(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IApplicationView3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_TitleBar(void**) noexcept = 0;
            virtual int32_t __stdcall get_FullScreenSystemOverlayMode(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_FullScreenSystemOverlayMode(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_IsFullScreenMode(bool*) noexcept = 0;
            virtual int32_t __stdcall TryEnterFullScreenMode(bool*) noexcept = 0;
            virtual int32_t __stdcall ExitFullScreenMode() noexcept = 0;
            virtual int32_t __stdcall ShowStandardSystemOverlays() noexcept = 0;
            virtual int32_t __stdcall TryResizeView(winrt::Windows::Foundation::Size, bool*) noexcept = 0;
            virtual int32_t __stdcall SetPreferredMinSize(winrt::Windows::Foundation::Size) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IApplicationView4>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ViewMode(int32_t*) noexcept = 0;
            virtual int32_t __stdcall IsViewModeSupported(int32_t, bool*) noexcept = 0;
            virtual int32_t __stdcall TryEnterViewModeAsync(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall TryEnterViewModeWithPreferencesAsync(int32_t, void*, void**) noexcept = 0;
            virtual int32_t __stdcall TryConsolidateAsync(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IApplicationView7>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PersistedStateId(void**) noexcept = 0;
            virtual int32_t __stdcall put_PersistedStateId(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IApplicationView9>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_WindowingEnvironment(void**) noexcept = 0;
            virtual int32_t __stdcall GetDisplayRegions(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsUserInitiated(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_IsAppInitiated(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IApplicationViewFullscreenStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall TryUnsnapToFullscreen(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IApplicationViewInteropStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetApplicationViewIdForWindow(void*, int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IApplicationViewScaling>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IApplicationViewScalingStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DisableLayoutScaling(bool*) noexcept = 0;
            virtual int32_t __stdcall TrySetDisableLayoutScaling(bool, bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IApplicationViewStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Value(int32_t*) noexcept = 0;
            virtual int32_t __stdcall TryUnsnap(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IApplicationViewStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetForCurrentView(void**) noexcept = 0;
            virtual int32_t __stdcall get_TerminateAppOnFinalViewClose(bool*) noexcept = 0;
            virtual int32_t __stdcall put_TerminateAppOnFinalViewClose(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IApplicationViewStatics3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_PreferredLaunchWindowingMode(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_PreferredLaunchWindowingMode(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_PreferredLaunchViewSize(winrt::Windows::Foundation::Size*) noexcept = 0;
            virtual int32_t __stdcall put_PreferredLaunchViewSize(winrt::Windows::Foundation::Size) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IApplicationViewStatics4>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ClearAllPersistedState() noexcept = 0;
            virtual int32_t __stdcall ClearPersistedState(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IApplicationViewSwitcherStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall DisableShowingMainViewOnActivation() noexcept = 0;
            virtual int32_t __stdcall TryShowAsStandaloneAsync(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall TryShowAsStandaloneWithSizePreferenceAsync(int32_t, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall TryShowAsStandaloneWithAnchorViewAndSizePreferenceAsync(int32_t, int32_t, int32_t, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall SwitchAsync(int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall SwitchFromViewAsync(int32_t, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall SwitchFromViewWithOptionsAsync(int32_t, int32_t, uint32_t, void**) noexcept = 0;
            virtual int32_t __stdcall PrepareForCustomAnimatedSwitchAsync(int32_t, int32_t, uint32_t, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IApplicationViewSwitcherStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall DisableSystemViewActivationPolicy() noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IApplicationViewSwitcherStatics3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall TryShowAsViewModeAsync(int32_t, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall TryShowAsViewModeWithPreferencesAsync(int32_t, int32_t, void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IApplicationViewTitleBar>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall put_ForegroundColor(void*) noexcept = 0;
            virtual int32_t __stdcall get_ForegroundColor(void**) noexcept = 0;
            virtual int32_t __stdcall put_BackgroundColor(void*) noexcept = 0;
            virtual int32_t __stdcall get_BackgroundColor(void**) noexcept = 0;
            virtual int32_t __stdcall put_ButtonForegroundColor(void*) noexcept = 0;
            virtual int32_t __stdcall get_ButtonForegroundColor(void**) noexcept = 0;
            virtual int32_t __stdcall put_ButtonBackgroundColor(void*) noexcept = 0;
            virtual int32_t __stdcall get_ButtonBackgroundColor(void**) noexcept = 0;
            virtual int32_t __stdcall put_ButtonHoverForegroundColor(void*) noexcept = 0;
            virtual int32_t __stdcall get_ButtonHoverForegroundColor(void**) noexcept = 0;
            virtual int32_t __stdcall put_ButtonHoverBackgroundColor(void*) noexcept = 0;
            virtual int32_t __stdcall get_ButtonHoverBackgroundColor(void**) noexcept = 0;
            virtual int32_t __stdcall put_ButtonPressedForegroundColor(void*) noexcept = 0;
            virtual int32_t __stdcall get_ButtonPressedForegroundColor(void**) noexcept = 0;
            virtual int32_t __stdcall put_ButtonPressedBackgroundColor(void*) noexcept = 0;
            virtual int32_t __stdcall get_ButtonPressedBackgroundColor(void**) noexcept = 0;
            virtual int32_t __stdcall put_InactiveForegroundColor(void*) noexcept = 0;
            virtual int32_t __stdcall get_InactiveForegroundColor(void**) noexcept = 0;
            virtual int32_t __stdcall put_InactiveBackgroundColor(void*) noexcept = 0;
            virtual int32_t __stdcall get_InactiveBackgroundColor(void**) noexcept = 0;
            virtual int32_t __stdcall put_ButtonInactiveForegroundColor(void*) noexcept = 0;
            virtual int32_t __stdcall get_ButtonInactiveForegroundColor(void**) noexcept = 0;
            virtual int32_t __stdcall put_ButtonInactiveBackgroundColor(void*) noexcept = 0;
            virtual int32_t __stdcall get_ButtonInactiveBackgroundColor(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IApplicationViewTransferContext>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ViewId(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ViewId(int32_t) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IApplicationViewTransferContextStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_DataPackageFormatId(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IApplicationViewWithContext>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_UIContext(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IInputPane>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall add_Showing(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Showing(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_Hiding(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Hiding(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall get_OccludedRect(winrt::Windows::Foundation::Rect*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IInputPane2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall TryShow(bool*) noexcept = 0;
            virtual int32_t __stdcall TryHide(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IInputPaneControl>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_Visible(bool*) noexcept = 0;
            virtual int32_t __stdcall put_Visible(bool) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IInputPaneStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetForCurrentView(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IInputPaneStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetForUIContext(void*, void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IInputPaneVisibilityEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_OccludedRect(winrt::Windows::Foundation::Rect*) noexcept = 0;
            virtual int32_t __stdcall put_EnsuredFocusedElementInView(bool) noexcept = 0;
            virtual int32_t __stdcall get_EnsuredFocusedElementInView(bool*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IProjectionManagerStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall StartProjectingAsync(int32_t, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall SwapDisplaysForViewsAsync(int32_t, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall StopProjectingAsync(int32_t, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall get_ProjectionDisplayAvailable(bool*) noexcept = 0;
            virtual int32_t __stdcall add_ProjectionDisplayAvailableChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ProjectionDisplayAvailableChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IProjectionManagerStatics2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall StartProjectingWithDeviceInfoAsync(int32_t, int32_t, void*, void**) noexcept = 0;
            virtual int32_t __stdcall RequestStartProjectingAsync(int32_t, int32_t, winrt::Windows::Foundation::Rect, void**) noexcept = 0;
            virtual int32_t __stdcall RequestStartProjectingWithPlacementAsync(int32_t, int32_t, winrt::Windows::Foundation::Rect, int32_t, void**) noexcept = 0;
            virtual int32_t __stdcall GetDeviceSelector(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IStatusBar>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ShowAsync(void**) noexcept = 0;
            virtual int32_t __stdcall HideAsync(void**) noexcept = 0;
            virtual int32_t __stdcall get_BackgroundOpacity(double*) noexcept = 0;
            virtual int32_t __stdcall put_BackgroundOpacity(double) noexcept = 0;
            virtual int32_t __stdcall get_ForegroundColor(void**) noexcept = 0;
            virtual int32_t __stdcall put_ForegroundColor(void*) noexcept = 0;
            virtual int32_t __stdcall get_BackgroundColor(void**) noexcept = 0;
            virtual int32_t __stdcall put_BackgroundColor(void*) noexcept = 0;
            virtual int32_t __stdcall get_ProgressIndicator(void**) noexcept = 0;
            virtual int32_t __stdcall get_OccludedRect(winrt::Windows::Foundation::Rect*) noexcept = 0;
            virtual int32_t __stdcall add_Showing(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Showing(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_Hiding(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_Hiding(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IStatusBarProgressIndicator>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall ShowAsync(void**) noexcept = 0;
            virtual int32_t __stdcall HideAsync(void**) noexcept = 0;
            virtual int32_t __stdcall get_Text(void**) noexcept = 0;
            virtual int32_t __stdcall put_Text(void*) noexcept = 0;
            virtual int32_t __stdcall get_ProgressValue(void**) noexcept = 0;
            virtual int32_t __stdcall put_ProgressValue(void*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IStatusBarStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetForCurrentView(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IUISettings>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_HandPreference(int32_t*) noexcept = 0;
            virtual int32_t __stdcall get_CursorSize(winrt::Windows::Foundation::Size*) noexcept = 0;
            virtual int32_t __stdcall get_ScrollBarSize(winrt::Windows::Foundation::Size*) noexcept = 0;
            virtual int32_t __stdcall get_ScrollBarArrowSize(winrt::Windows::Foundation::Size*) noexcept = 0;
            virtual int32_t __stdcall get_ScrollBarThumbBoxSize(winrt::Windows::Foundation::Size*) noexcept = 0;
            virtual int32_t __stdcall get_MessageDuration(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_AnimationsEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall get_CaretBrowsingEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall get_CaretBlinkRate(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_CaretWidth(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_DoubleClickTime(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall get_MouseHoverTime(uint32_t*) noexcept = 0;
            virtual int32_t __stdcall UIElementColor(int32_t, struct struct_Windows_UI_Color*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IUISettings2>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_TextScaleFactor(double*) noexcept = 0;
            virtual int32_t __stdcall add_TextScaleFactorChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_TextScaleFactorChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IUISettings3>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetColorValue(int32_t, struct struct_Windows_UI_Color*) noexcept = 0;
            virtual int32_t __stdcall add_ColorValuesChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_ColorValuesChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IUISettings4>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AdvancedEffectsEnabled(bool*) noexcept = 0;
            virtual int32_t __stdcall add_AdvancedEffectsEnabledChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_AdvancedEffectsEnabledChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IUISettings5>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_AutoHideScrollBars(bool*) noexcept = 0;
            virtual int32_t __stdcall add_AutoHideScrollBarsChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_AutoHideScrollBarsChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IUISettings6>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall add_AnimationsEnabledChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_AnimationsEnabledChanged(winrt::event_token) noexcept = 0;
            virtual int32_t __stdcall add_MessageDurationChanged(void*, winrt::event_token*) noexcept = 0;
            virtual int32_t __stdcall remove_MessageDurationChanged(winrt::event_token) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IUISettingsAnimationsEnabledChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IUISettingsAutoHideScrollBarsChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IUISettingsMessageDurationChangedEventArgs>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IUIViewSettings>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_UserInteractionMode(int32_t*) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IUIViewSettingsStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall GetForCurrentView(void**) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IViewModePreferences>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall get_ViewSizePreference(int32_t*) noexcept = 0;
            virtual int32_t __stdcall put_ViewSizePreference(int32_t) noexcept = 0;
            virtual int32_t __stdcall get_CustomSize(winrt::Windows::Foundation::Size*) noexcept = 0;
            virtual int32_t __stdcall put_CustomSize(winrt::Windows::Foundation::Size) noexcept = 0;
        };
    };
    template <> struct abi<winrt::Windows::UI::ViewManagement::IViewModePreferencesStatics>
    {
        struct __declspec(novtable) type : inspectable_abi
        {
            virtual int32_t __stdcall CreateDefault(int32_t, void**) noexcept = 0;
        };
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IAccessibilitySettings
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) HighContrast() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) HighContrastScheme() const;
        WINRT_IMPL_AUTO(winrt::event_token) HighContrastChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::AccessibilitySettings, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using HighContrastChanged_revoker = impl::event_revoker<winrt::Windows::UI::ViewManagement::IAccessibilitySettings, &impl::abi_t<winrt::Windows::UI::ViewManagement::IAccessibilitySettings>::remove_HighContrastChanged>;
        [[nodiscard]] HighContrastChanged_revoker HighContrastChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::AccessibilitySettings, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) HighContrastChanged(winrt::event_token const& cookie) const noexcept;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IAccessibilitySettings>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IAccessibilitySettings<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IActivationViewSwitcher
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ShowAsStandaloneAsync(int32_t viewId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ShowAsStandaloneAsync(int32_t viewId, winrt::Windows::UI::ViewManagement::ViewSizePreference const& sizePreference) const;
        WINRT_IMPL_AUTO(bool) IsViewPresentedOnActivationVirtualDesktop(int32_t viewId) const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IActivationViewSwitcher>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IActivationViewSwitcher<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IApplicationView
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::ViewManagement::ApplicationViewOrientation) Orientation() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AdjacentToLeftDisplayEdge() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AdjacentToRightDisplayEdge() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsFullScreen() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsOnLockScreen() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsScreenCaptureEnabled() const;
        WINRT_IMPL_AUTO(void) IsScreenCaptureEnabled(bool value) const;
        WINRT_IMPL_AUTO(void) Title(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Title() const;
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) Id() const;
        WINRT_IMPL_AUTO(winrt::event_token) Consolidated(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::ApplicationView, winrt::Windows::UI::ViewManagement::ApplicationViewConsolidatedEventArgs> const& handler) const;
        using Consolidated_revoker = impl::event_revoker<winrt::Windows::UI::ViewManagement::IApplicationView, &impl::abi_t<winrt::Windows::UI::ViewManagement::IApplicationView>::remove_Consolidated>;
        [[nodiscard]] Consolidated_revoker Consolidated(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::ApplicationView, winrt::Windows::UI::ViewManagement::ApplicationViewConsolidatedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) Consolidated(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IApplicationView>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationView<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IApplicationView2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) SuppressSystemOverlays() const;
        WINRT_IMPL_AUTO(void) SuppressSystemOverlays(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) VisibleBounds() const;
        WINRT_IMPL_AUTO(winrt::event_token) VisibleBoundsChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::ApplicationView, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using VisibleBoundsChanged_revoker = impl::event_revoker<winrt::Windows::UI::ViewManagement::IApplicationView2, &impl::abi_t<winrt::Windows::UI::ViewManagement::IApplicationView2>::remove_VisibleBoundsChanged>;
        [[nodiscard]] VisibleBoundsChanged_revoker VisibleBoundsChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::ApplicationView, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) VisibleBoundsChanged(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(bool) SetDesiredBoundsMode(winrt::Windows::UI::ViewManagement::ApplicationViewBoundsMode const& boundsMode) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::ViewManagement::ApplicationViewBoundsMode) DesiredBoundsMode() const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IApplicationView2>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationView2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IApplicationView3
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::ViewManagement::ApplicationViewTitleBar) TitleBar() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::ViewManagement::FullScreenSystemOverlayMode) FullScreenSystemOverlayMode() const;
        WINRT_IMPL_AUTO(void) FullScreenSystemOverlayMode(winrt::Windows::UI::ViewManagement::FullScreenSystemOverlayMode const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsFullScreenMode() const;
        WINRT_IMPL_AUTO(bool) TryEnterFullScreenMode() const;
        WINRT_IMPL_AUTO(void) ExitFullScreenMode() const;
        WINRT_IMPL_AUTO(void) ShowStandardSystemOverlays() const;
        WINRT_IMPL_AUTO(bool) TryResizeView(winrt::Windows::Foundation::Size const& value) const;
        WINRT_IMPL_AUTO(void) SetPreferredMinSize(winrt::Windows::Foundation::Size const& minSize) const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IApplicationView3>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationView3<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IApplicationView4
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::ViewManagement::ApplicationViewMode) ViewMode() const;
        WINRT_IMPL_AUTO(bool) IsViewModeSupported(winrt::Windows::UI::ViewManagement::ApplicationViewMode const& viewMode) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TryEnterViewModeAsync(winrt::Windows::UI::ViewManagement::ApplicationViewMode const& viewMode) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TryEnterViewModeAsync(winrt::Windows::UI::ViewManagement::ApplicationViewMode const& viewMode, winrt::Windows::UI::ViewManagement::ViewModePreferences const& viewModePreferences) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TryConsolidateAsync() const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IApplicationView4>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationView4<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IApplicationView7
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) PersistedStateId() const;
        WINRT_IMPL_AUTO(void) PersistedStateId(param::hstring const& value) const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IApplicationView7>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationView7<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IApplicationView9
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::WindowManagement::WindowingEnvironment) WindowingEnvironment() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::Collections::IVectorView<winrt::Windows::UI::WindowManagement::DisplayRegion>) GetDisplayRegions() const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IApplicationView9>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationView9<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IApplicationViewConsolidatedEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsUserInitiated() const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewConsolidatedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IApplicationViewConsolidatedEventArgs2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) IsAppInitiated() const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IApplicationViewConsolidatedEventArgs2>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewConsolidatedEventArgs2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IApplicationViewFullscreenStatics
    {
        WINRT_IMPL_AUTO(bool) TryUnsnapToFullscreen() const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IApplicationViewFullscreenStatics>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewFullscreenStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IApplicationViewInteropStatics
    {
        WINRT_IMPL_AUTO(int32_t) GetApplicationViewIdForWindow(winrt::Windows::UI::Core::ICoreWindow const& window) const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IApplicationViewInteropStatics>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewInteropStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IApplicationViewScaling
    {
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IApplicationViewScaling>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewScaling<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IApplicationViewScalingStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) DisableLayoutScaling() const;
        WINRT_IMPL_AUTO(bool) TrySetDisableLayoutScaling(bool disableLayoutScaling) const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IApplicationViewScalingStatics>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewScalingStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IApplicationViewStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::ViewManagement::ApplicationViewState) Value() const;
        WINRT_IMPL_AUTO(bool) TryUnsnap() const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IApplicationViewStatics>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IApplicationViewStatics2
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::ViewManagement::ApplicationView) GetForCurrentView() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) TerminateAppOnFinalViewClose() const;
        WINRT_IMPL_AUTO(void) TerminateAppOnFinalViewClose(bool value) const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IApplicationViewStatics2>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IApplicationViewStatics3
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::ViewManagement::ApplicationViewWindowingMode) PreferredLaunchWindowingMode() const;
        WINRT_IMPL_AUTO(void) PreferredLaunchWindowingMode(winrt::Windows::UI::ViewManagement::ApplicationViewWindowingMode const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) PreferredLaunchViewSize() const;
        WINRT_IMPL_AUTO(void) PreferredLaunchViewSize(winrt::Windows::Foundation::Size const& value) const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IApplicationViewStatics3>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewStatics3<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IApplicationViewStatics4
    {
        WINRT_IMPL_AUTO(void) ClearAllPersistedState() const;
        WINRT_IMPL_AUTO(void) ClearPersistedState(param::hstring const& key) const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IApplicationViewStatics4>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewStatics4<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IApplicationViewSwitcherStatics
    {
        WINRT_IMPL_AUTO(void) DisableShowingMainViewOnActivation() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TryShowAsStandaloneAsync(int32_t viewId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TryShowAsStandaloneAsync(int32_t viewId, winrt::Windows::UI::ViewManagement::ViewSizePreference const& sizePreference) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TryShowAsStandaloneAsync(int32_t viewId, winrt::Windows::UI::ViewManagement::ViewSizePreference const& sizePreference, int32_t anchorViewId, winrt::Windows::UI::ViewManagement::ViewSizePreference const& anchorSizePreference) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) SwitchAsync(int32_t viewId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) SwitchAsync(int32_t toViewId, int32_t fromViewId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) SwitchAsync(int32_t toViewId, int32_t fromViewId, winrt::Windows::UI::ViewManagement::ApplicationViewSwitchingOptions const& options) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) PrepareForCustomAnimatedSwitchAsync(int32_t toViewId, int32_t fromViewId, winrt::Windows::UI::ViewManagement::ApplicationViewSwitchingOptions const& options) const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IApplicationViewSwitcherStatics>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewSwitcherStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IApplicationViewSwitcherStatics2
    {
        WINRT_IMPL_AUTO(void) DisableSystemViewActivationPolicy() const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IApplicationViewSwitcherStatics2>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewSwitcherStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IApplicationViewSwitcherStatics3
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TryShowAsViewModeAsync(int32_t viewId, winrt::Windows::UI::ViewManagement::ApplicationViewMode const& viewMode) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) TryShowAsViewModeAsync(int32_t viewId, winrt::Windows::UI::ViewManagement::ApplicationViewMode const& viewMode, winrt::Windows::UI::ViewManagement::ViewModePreferences const& viewModePreferences) const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IApplicationViewSwitcherStatics3>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewSwitcherStatics3<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IApplicationViewTitleBar
    {
        WINRT_IMPL_AUTO(void) ForegroundColor(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) ForegroundColor() const;
        WINRT_IMPL_AUTO(void) BackgroundColor(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) BackgroundColor() const;
        WINRT_IMPL_AUTO(void) ButtonForegroundColor(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) ButtonForegroundColor() const;
        WINRT_IMPL_AUTO(void) ButtonBackgroundColor(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) ButtonBackgroundColor() const;
        WINRT_IMPL_AUTO(void) ButtonHoverForegroundColor(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) ButtonHoverForegroundColor() const;
        WINRT_IMPL_AUTO(void) ButtonHoverBackgroundColor(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) ButtonHoverBackgroundColor() const;
        WINRT_IMPL_AUTO(void) ButtonPressedForegroundColor(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) ButtonPressedForegroundColor() const;
        WINRT_IMPL_AUTO(void) ButtonPressedBackgroundColor(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) ButtonPressedBackgroundColor() const;
        WINRT_IMPL_AUTO(void) InactiveForegroundColor(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) InactiveForegroundColor() const;
        WINRT_IMPL_AUTO(void) InactiveBackgroundColor(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) InactiveBackgroundColor() const;
        WINRT_IMPL_AUTO(void) ButtonInactiveForegroundColor(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) ButtonInactiveForegroundColor() const;
        WINRT_IMPL_AUTO(void) ButtonInactiveBackgroundColor(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) ButtonInactiveBackgroundColor() const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IApplicationViewTitleBar>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewTitleBar<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IApplicationViewTransferContext
    {
        [[nodiscard]] WINRT_IMPL_AUTO(int32_t) ViewId() const;
        WINRT_IMPL_AUTO(void) ViewId(int32_t value) const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IApplicationViewTransferContext>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewTransferContext<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IApplicationViewTransferContextStatics
    {
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) DataPackageFormatId() const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IApplicationViewTransferContextStatics>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewTransferContextStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IApplicationViewWithContext
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::UIContext) UIContext() const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IApplicationViewWithContext>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IApplicationViewWithContext<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IInputPane
    {
        WINRT_IMPL_AUTO(winrt::event_token) Showing(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::InputPane, winrt::Windows::UI::ViewManagement::InputPaneVisibilityEventArgs> const& handler) const;
        using Showing_revoker = impl::event_revoker<winrt::Windows::UI::ViewManagement::IInputPane, &impl::abi_t<winrt::Windows::UI::ViewManagement::IInputPane>::remove_Showing>;
        [[nodiscard]] Showing_revoker Showing(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::InputPane, winrt::Windows::UI::ViewManagement::InputPaneVisibilityEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) Showing(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) Hiding(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::InputPane, winrt::Windows::UI::ViewManagement::InputPaneVisibilityEventArgs> const& handler) const;
        using Hiding_revoker = impl::event_revoker<winrt::Windows::UI::ViewManagement::IInputPane, &impl::abi_t<winrt::Windows::UI::ViewManagement::IInputPane>::remove_Hiding>;
        [[nodiscard]] Hiding_revoker Hiding(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::InputPane, winrt::Windows::UI::ViewManagement::InputPaneVisibilityEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) Hiding(winrt::event_token const& token) const noexcept;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) OccludedRect() const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IInputPane>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IInputPane<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IInputPane2
    {
        WINRT_IMPL_AUTO(bool) TryShow() const;
        WINRT_IMPL_AUTO(bool) TryHide() const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IInputPane2>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IInputPane2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IInputPaneControl
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) Visible() const;
        WINRT_IMPL_AUTO(void) Visible(bool value) const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IInputPaneControl>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IInputPaneControl<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IInputPaneStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::ViewManagement::InputPane) GetForCurrentView() const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IInputPaneStatics>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IInputPaneStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IInputPaneStatics2
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::ViewManagement::InputPane) GetForUIContext(winrt::Windows::UI::UIContext const& context) const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IInputPaneStatics2>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IInputPaneStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IInputPaneVisibilityEventArgs
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) OccludedRect() const;
        WINRT_IMPL_AUTO(void) EnsuredFocusedElementInView(bool value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) EnsuredFocusedElementInView() const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IInputPaneVisibilityEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IInputPaneVisibilityEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IProjectionManagerStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) StartProjectingAsync(int32_t projectionViewId, int32_t anchorViewId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) SwapDisplaysForViewsAsync(int32_t projectionViewId, int32_t anchorViewId) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) StopProjectingAsync(int32_t projectionViewId, int32_t anchorViewId) const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) ProjectionDisplayAvailable() const;
        WINRT_IMPL_AUTO(winrt::event_token) ProjectionDisplayAvailableChanged(winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const;
        using ProjectionDisplayAvailableChanged_revoker = impl::event_revoker<winrt::Windows::UI::ViewManagement::IProjectionManagerStatics, &impl::abi_t<winrt::Windows::UI::ViewManagement::IProjectionManagerStatics>::remove_ProjectionDisplayAvailableChanged>;
        [[nodiscard]] ProjectionDisplayAvailableChanged_revoker ProjectionDisplayAvailableChanged(auto_revoke_t, winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) ProjectionDisplayAvailableChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IProjectionManagerStatics>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IProjectionManagerStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IProjectionManagerStatics2
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) StartProjectingAsync(int32_t projectionViewId, int32_t anchorViewId, winrt::Windows::Devices::Enumeration::DeviceInformation const& displayDeviceInfo) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) RequestStartProjectingAsync(int32_t projectionViewId, int32_t anchorViewId, winrt::Windows::Foundation::Rect const& selection) const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncOperation<bool>) RequestStartProjectingAsync(int32_t projectionViewId, int32_t anchorViewId, winrt::Windows::Foundation::Rect const& selection, winrt::Windows::UI::Popups::Placement const& prefferedPlacement) const;
        WINRT_IMPL_AUTO(hstring) GetDeviceSelector() const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IProjectionManagerStatics2>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IProjectionManagerStatics2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IStatusBar
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ShowAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) HideAsync() const;
        [[nodiscard]] WINRT_IMPL_AUTO(double) BackgroundOpacity() const;
        WINRT_IMPL_AUTO(void) BackgroundOpacity(double value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) ForegroundColor() const;
        WINRT_IMPL_AUTO(void) ForegroundColor(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color>) BackgroundColor() const;
        WINRT_IMPL_AUTO(void) BackgroundColor(winrt::Windows::Foundation::IReference<winrt::Windows::UI::Color> const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::ViewManagement::StatusBarProgressIndicator) ProgressIndicator() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Rect) OccludedRect() const;
        WINRT_IMPL_AUTO(winrt::event_token) Showing(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::StatusBar, winrt::Windows::Foundation::IInspectable> const& eventHandler) const;
        using Showing_revoker = impl::event_revoker<winrt::Windows::UI::ViewManagement::IStatusBar, &impl::abi_t<winrt::Windows::UI::ViewManagement::IStatusBar>::remove_Showing>;
        [[nodiscard]] Showing_revoker Showing(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::StatusBar, winrt::Windows::Foundation::IInspectable> const& eventHandler) const;
        WINRT_IMPL_AUTO(void) Showing(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) Hiding(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::StatusBar, winrt::Windows::Foundation::IInspectable> const& eventHandler) const;
        using Hiding_revoker = impl::event_revoker<winrt::Windows::UI::ViewManagement::IStatusBar, &impl::abi_t<winrt::Windows::UI::ViewManagement::IStatusBar>::remove_Hiding>;
        [[nodiscard]] Hiding_revoker Hiding(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::StatusBar, winrt::Windows::Foundation::IInspectable> const& eventHandler) const;
        WINRT_IMPL_AUTO(void) Hiding(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IStatusBar>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IStatusBar<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IStatusBarProgressIndicator
    {
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) ShowAsync() const;
        WINRT_IMPL_AUTO(winrt::Windows::Foundation::IAsyncAction) HideAsync() const;
        [[nodiscard]] WINRT_IMPL_AUTO(hstring) Text() const;
        WINRT_IMPL_AUTO(void) Text(param::hstring const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::IReference<double>) ProgressValue() const;
        WINRT_IMPL_AUTO(void) ProgressValue(winrt::Windows::Foundation::IReference<double> const& value) const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IStatusBarProgressIndicator>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IStatusBarProgressIndicator<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IStatusBarStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::ViewManagement::StatusBar) GetForCurrentView() const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IStatusBarStatics>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IStatusBarStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IUISettings
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::ViewManagement::HandPreference) HandPreference() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) CursorSize() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) ScrollBarSize() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) ScrollBarArrowSize() const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) ScrollBarThumbBoxSize() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MessageDuration() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AnimationsEnabled() const;
        [[nodiscard]] WINRT_IMPL_AUTO(bool) CaretBrowsingEnabled() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) CaretBlinkRate() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) CaretWidth() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) DoubleClickTime() const;
        [[nodiscard]] WINRT_IMPL_AUTO(uint32_t) MouseHoverTime() const;
        WINRT_IMPL_AUTO(winrt::Windows::UI::Color) UIElementColor(winrt::Windows::UI::ViewManagement::UIElementType const& desiredElement) const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IUISettings>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IUISettings<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IUISettings2
    {
        [[nodiscard]] WINRT_IMPL_AUTO(double) TextScaleFactor() const;
        WINRT_IMPL_AUTO(winrt::event_token) TextScaleFactorChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::UISettings, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using TextScaleFactorChanged_revoker = impl::event_revoker<winrt::Windows::UI::ViewManagement::IUISettings2, &impl::abi_t<winrt::Windows::UI::ViewManagement::IUISettings2>::remove_TextScaleFactorChanged>;
        [[nodiscard]] TextScaleFactorChanged_revoker TextScaleFactorChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::UISettings, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) TextScaleFactorChanged(winrt::event_token const& cookie) const noexcept;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IUISettings2>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IUISettings2<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IUISettings3
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::Color) GetColorValue(winrt::Windows::UI::ViewManagement::UIColorType const& desiredColor) const;
        WINRT_IMPL_AUTO(winrt::event_token) ColorValuesChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::UISettings, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using ColorValuesChanged_revoker = impl::event_revoker<winrt::Windows::UI::ViewManagement::IUISettings3, &impl::abi_t<winrt::Windows::UI::ViewManagement::IUISettings3>::remove_ColorValuesChanged>;
        [[nodiscard]] ColorValuesChanged_revoker ColorValuesChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::UISettings, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) ColorValuesChanged(winrt::event_token const& cookie) const noexcept;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IUISettings3>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IUISettings3<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IUISettings4
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AdvancedEffectsEnabled() const;
        WINRT_IMPL_AUTO(winrt::event_token) AdvancedEffectsEnabledChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::UISettings, winrt::Windows::Foundation::IInspectable> const& handler) const;
        using AdvancedEffectsEnabledChanged_revoker = impl::event_revoker<winrt::Windows::UI::ViewManagement::IUISettings4, &impl::abi_t<winrt::Windows::UI::ViewManagement::IUISettings4>::remove_AdvancedEffectsEnabledChanged>;
        [[nodiscard]] AdvancedEffectsEnabledChanged_revoker AdvancedEffectsEnabledChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::UISettings, winrt::Windows::Foundation::IInspectable> const& handler) const;
        WINRT_IMPL_AUTO(void) AdvancedEffectsEnabledChanged(winrt::event_token const& cookie) const noexcept;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IUISettings4>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IUISettings4<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IUISettings5
    {
        [[nodiscard]] WINRT_IMPL_AUTO(bool) AutoHideScrollBars() const;
        WINRT_IMPL_AUTO(winrt::event_token) AutoHideScrollBarsChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::UISettings, winrt::Windows::UI::ViewManagement::UISettingsAutoHideScrollBarsChangedEventArgs> const& handler) const;
        using AutoHideScrollBarsChanged_revoker = impl::event_revoker<winrt::Windows::UI::ViewManagement::IUISettings5, &impl::abi_t<winrt::Windows::UI::ViewManagement::IUISettings5>::remove_AutoHideScrollBarsChanged>;
        [[nodiscard]] AutoHideScrollBarsChanged_revoker AutoHideScrollBarsChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::UISettings, winrt::Windows::UI::ViewManagement::UISettingsAutoHideScrollBarsChangedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) AutoHideScrollBarsChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IUISettings5>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IUISettings5<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IUISettings6
    {
        WINRT_IMPL_AUTO(winrt::event_token) AnimationsEnabledChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::UISettings, winrt::Windows::UI::ViewManagement::UISettingsAnimationsEnabledChangedEventArgs> const& handler) const;
        using AnimationsEnabledChanged_revoker = impl::event_revoker<winrt::Windows::UI::ViewManagement::IUISettings6, &impl::abi_t<winrt::Windows::UI::ViewManagement::IUISettings6>::remove_AnimationsEnabledChanged>;
        [[nodiscard]] AnimationsEnabledChanged_revoker AnimationsEnabledChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::UISettings, winrt::Windows::UI::ViewManagement::UISettingsAnimationsEnabledChangedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) AnimationsEnabledChanged(winrt::event_token const& token) const noexcept;
        WINRT_IMPL_AUTO(winrt::event_token) MessageDurationChanged(winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::UISettings, winrt::Windows::UI::ViewManagement::UISettingsMessageDurationChangedEventArgs> const& handler) const;
        using MessageDurationChanged_revoker = impl::event_revoker<winrt::Windows::UI::ViewManagement::IUISettings6, &impl::abi_t<winrt::Windows::UI::ViewManagement::IUISettings6>::remove_MessageDurationChanged>;
        [[nodiscard]] MessageDurationChanged_revoker MessageDurationChanged(auto_revoke_t, winrt::Windows::Foundation::TypedEventHandler<winrt::Windows::UI::ViewManagement::UISettings, winrt::Windows::UI::ViewManagement::UISettingsMessageDurationChangedEventArgs> const& handler) const;
        WINRT_IMPL_AUTO(void) MessageDurationChanged(winrt::event_token const& token) const noexcept;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IUISettings6>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IUISettings6<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IUISettingsAnimationsEnabledChangedEventArgs
    {
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IUISettingsAnimationsEnabledChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IUISettingsAnimationsEnabledChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IUISettingsAutoHideScrollBarsChangedEventArgs
    {
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IUISettingsAutoHideScrollBarsChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IUISettingsAutoHideScrollBarsChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IUISettingsMessageDurationChangedEventArgs
    {
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IUISettingsMessageDurationChangedEventArgs>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IUISettingsMessageDurationChangedEventArgs<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IUIViewSettings
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::ViewManagement::UserInteractionMode) UserInteractionMode() const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IUIViewSettings>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IUIViewSettings<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IUIViewSettingsStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::ViewManagement::UIViewSettings) GetForCurrentView() const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IUIViewSettingsStatics>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IUIViewSettingsStatics<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IViewModePreferences
    {
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::UI::ViewManagement::ViewSizePreference) ViewSizePreference() const;
        WINRT_IMPL_AUTO(void) ViewSizePreference(winrt::Windows::UI::ViewManagement::ViewSizePreference const& value) const;
        [[nodiscard]] WINRT_IMPL_AUTO(winrt::Windows::Foundation::Size) CustomSize() const;
        WINRT_IMPL_AUTO(void) CustomSize(winrt::Windows::Foundation::Size const& value) const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IViewModePreferences>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IViewModePreferences<D>;
    };
    template <typename D>
    struct consume_Windows_UI_ViewManagement_IViewModePreferencesStatics
    {
        WINRT_IMPL_AUTO(winrt::Windows::UI::ViewManagement::ViewModePreferences) CreateDefault(winrt::Windows::UI::ViewManagement::ApplicationViewMode const& mode) const;
    };
    template <> struct consume<winrt::Windows::UI::ViewManagement::IViewModePreferencesStatics>
    {
        template <typename D> using type = consume_Windows_UI_ViewManagement_IViewModePreferencesStatics<D>;
    };
}
#endif
