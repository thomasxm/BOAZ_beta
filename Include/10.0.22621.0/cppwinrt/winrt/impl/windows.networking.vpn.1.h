// C++/WinRT v2.0.220110.5

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef WINRT_Windows_Networking_Vpn_1_H
#define WINRT_Windows_Networking_Vpn_1_H
#include "winrt/impl/Windows.Foundation.Collections.0.h"
#include "winrt/impl/Windows.Networking.Vpn.0.h"
WINRT_EXPORT namespace winrt::Windows::Networking::Vpn
{
    struct __declspec(empty_bases) IVpnAppId :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnAppId>
    {
        IVpnAppId(std::nullptr_t = nullptr) noexcept {}
        IVpnAppId(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnAppIdFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnAppIdFactory>
    {
        IVpnAppIdFactory(std::nullptr_t = nullptr) noexcept {}
        IVpnAppIdFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnChannel :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnChannel>
    {
        IVpnChannel(std::nullptr_t = nullptr) noexcept {}
        IVpnChannel(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnChannel2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnChannel2>
    {
        IVpnChannel2(std::nullptr_t = nullptr) noexcept {}
        IVpnChannel2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnChannel4 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnChannel4>
    {
        IVpnChannel4(std::nullptr_t = nullptr) noexcept {}
        IVpnChannel4(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnChannel5 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnChannel5>
    {
        IVpnChannel5(std::nullptr_t = nullptr) noexcept {}
        IVpnChannel5(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnChannel6 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnChannel6>
    {
        IVpnChannel6(std::nullptr_t = nullptr) noexcept {}
        IVpnChannel6(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnChannelActivityEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnChannelActivityEventArgs>
    {
        IVpnChannelActivityEventArgs(std::nullptr_t = nullptr) noexcept {}
        IVpnChannelActivityEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnChannelActivityStateChangedArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnChannelActivityStateChangedArgs>
    {
        IVpnChannelActivityStateChangedArgs(std::nullptr_t = nullptr) noexcept {}
        IVpnChannelActivityStateChangedArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnChannelConfiguration :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnChannelConfiguration>
    {
        IVpnChannelConfiguration(std::nullptr_t = nullptr) noexcept {}
        IVpnChannelConfiguration(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnChannelConfiguration2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnChannelConfiguration2>
    {
        IVpnChannelConfiguration2(std::nullptr_t = nullptr) noexcept {}
        IVpnChannelConfiguration2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnChannelStatics :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnChannelStatics>
    {
        IVpnChannelStatics(std::nullptr_t = nullptr) noexcept {}
        IVpnChannelStatics(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnCredential :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnCredential>
    {
        IVpnCredential(std::nullptr_t = nullptr) noexcept {}
        IVpnCredential(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnCustomCheckBox :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnCustomCheckBox>,
        impl::require<winrt::Windows::Networking::Vpn::IVpnCustomCheckBox, winrt::Windows::Networking::Vpn::IVpnCustomPrompt>
    {
        IVpnCustomCheckBox(std::nullptr_t = nullptr) noexcept {}
        IVpnCustomCheckBox(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnCustomComboBox :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnCustomComboBox>,
        impl::require<winrt::Windows::Networking::Vpn::IVpnCustomComboBox, winrt::Windows::Networking::Vpn::IVpnCustomPrompt>
    {
        IVpnCustomComboBox(std::nullptr_t = nullptr) noexcept {}
        IVpnCustomComboBox(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnCustomEditBox :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnCustomEditBox>,
        impl::require<winrt::Windows::Networking::Vpn::IVpnCustomEditBox, winrt::Windows::Networking::Vpn::IVpnCustomPrompt>
    {
        IVpnCustomEditBox(std::nullptr_t = nullptr) noexcept {}
        IVpnCustomEditBox(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnCustomErrorBox :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnCustomErrorBox>,
        impl::require<winrt::Windows::Networking::Vpn::IVpnCustomErrorBox, winrt::Windows::Networking::Vpn::IVpnCustomPrompt>
    {
        IVpnCustomErrorBox(std::nullptr_t = nullptr) noexcept {}
        IVpnCustomErrorBox(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnCustomPrompt :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnCustomPrompt>
    {
        IVpnCustomPrompt(std::nullptr_t = nullptr) noexcept {}
        IVpnCustomPrompt(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnCustomPromptBooleanInput :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnCustomPromptBooleanInput>,
        impl::require<winrt::Windows::Networking::Vpn::IVpnCustomPromptBooleanInput, winrt::Windows::Networking::Vpn::IVpnCustomPromptElement>
    {
        IVpnCustomPromptBooleanInput(std::nullptr_t = nullptr) noexcept {}
        IVpnCustomPromptBooleanInput(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnCustomPromptElement :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnCustomPromptElement>
    {
        IVpnCustomPromptElement(std::nullptr_t = nullptr) noexcept {}
        IVpnCustomPromptElement(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnCustomPromptOptionSelector :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnCustomPromptOptionSelector>,
        impl::require<winrt::Windows::Networking::Vpn::IVpnCustomPromptOptionSelector, winrt::Windows::Networking::Vpn::IVpnCustomPromptElement>
    {
        IVpnCustomPromptOptionSelector(std::nullptr_t = nullptr) noexcept {}
        IVpnCustomPromptOptionSelector(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnCustomPromptText :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnCustomPromptText>,
        impl::require<winrt::Windows::Networking::Vpn::IVpnCustomPromptText, winrt::Windows::Networking::Vpn::IVpnCustomPromptElement>
    {
        IVpnCustomPromptText(std::nullptr_t = nullptr) noexcept {}
        IVpnCustomPromptText(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnCustomPromptTextInput :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnCustomPromptTextInput>,
        impl::require<winrt::Windows::Networking::Vpn::IVpnCustomPromptTextInput, winrt::Windows::Networking::Vpn::IVpnCustomPromptElement>
    {
        IVpnCustomPromptTextInput(std::nullptr_t = nullptr) noexcept {}
        IVpnCustomPromptTextInput(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnCustomTextBox :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnCustomTextBox>,
        impl::require<winrt::Windows::Networking::Vpn::IVpnCustomTextBox, winrt::Windows::Networking::Vpn::IVpnCustomPrompt>
    {
        IVpnCustomTextBox(std::nullptr_t = nullptr) noexcept {}
        IVpnCustomTextBox(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnDomainNameAssignment :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnDomainNameAssignment>
    {
        IVpnDomainNameAssignment(std::nullptr_t = nullptr) noexcept {}
        IVpnDomainNameAssignment(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnDomainNameInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnDomainNameInfo>
    {
        IVpnDomainNameInfo(std::nullptr_t = nullptr) noexcept {}
        IVpnDomainNameInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnDomainNameInfo2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnDomainNameInfo2>
    {
        IVpnDomainNameInfo2(std::nullptr_t = nullptr) noexcept {}
        IVpnDomainNameInfo2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnDomainNameInfoFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnDomainNameInfoFactory>
    {
        IVpnDomainNameInfoFactory(std::nullptr_t = nullptr) noexcept {}
        IVpnDomainNameInfoFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnForegroundActivatedEventArgs :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnForegroundActivatedEventArgs>
    {
        IVpnForegroundActivatedEventArgs(std::nullptr_t = nullptr) noexcept {}
        IVpnForegroundActivatedEventArgs(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnForegroundActivationOperation :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnForegroundActivationOperation>
    {
        IVpnForegroundActivationOperation(std::nullptr_t = nullptr) noexcept {}
        IVpnForegroundActivationOperation(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnInterfaceId :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnInterfaceId>
    {
        IVpnInterfaceId(std::nullptr_t = nullptr) noexcept {}
        IVpnInterfaceId(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnInterfaceIdFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnInterfaceIdFactory>
    {
        IVpnInterfaceIdFactory(std::nullptr_t = nullptr) noexcept {}
        IVpnInterfaceIdFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnManagementAgent :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnManagementAgent>
    {
        IVpnManagementAgent(std::nullptr_t = nullptr) noexcept {}
        IVpnManagementAgent(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnNamespaceAssignment :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnNamespaceAssignment>
    {
        IVpnNamespaceAssignment(std::nullptr_t = nullptr) noexcept {}
        IVpnNamespaceAssignment(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnNamespaceInfo :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnNamespaceInfo>
    {
        IVpnNamespaceInfo(std::nullptr_t = nullptr) noexcept {}
        IVpnNamespaceInfo(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnNamespaceInfoFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnNamespaceInfoFactory>
    {
        IVpnNamespaceInfoFactory(std::nullptr_t = nullptr) noexcept {}
        IVpnNamespaceInfoFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnNativeProfile :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnNativeProfile>,
        impl::require<winrt::Windows::Networking::Vpn::IVpnNativeProfile, winrt::Windows::Networking::Vpn::IVpnProfile>
    {
        IVpnNativeProfile(std::nullptr_t = nullptr) noexcept {}
        IVpnNativeProfile(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnNativeProfile2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnNativeProfile2>
    {
        IVpnNativeProfile2(std::nullptr_t = nullptr) noexcept {}
        IVpnNativeProfile2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnPacketBuffer :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnPacketBuffer>
    {
        IVpnPacketBuffer(std::nullptr_t = nullptr) noexcept {}
        IVpnPacketBuffer(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnPacketBuffer2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnPacketBuffer2>
    {
        IVpnPacketBuffer2(std::nullptr_t = nullptr) noexcept {}
        IVpnPacketBuffer2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnPacketBuffer3 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnPacketBuffer3>
    {
        IVpnPacketBuffer3(std::nullptr_t = nullptr) noexcept {}
        IVpnPacketBuffer3(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnPacketBufferFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnPacketBufferFactory>
    {
        IVpnPacketBufferFactory(std::nullptr_t = nullptr) noexcept {}
        IVpnPacketBufferFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnPacketBufferList :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnPacketBufferList>,
        impl::require<winrt::Windows::Networking::Vpn::IVpnPacketBufferList, winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Networking::Vpn::VpnPacketBuffer>>
    {
        IVpnPacketBufferList(std::nullptr_t = nullptr) noexcept {}
        IVpnPacketBufferList(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnPacketBufferList2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnPacketBufferList2>,
        impl::require<winrt::Windows::Networking::Vpn::IVpnPacketBufferList2, winrt::Windows::Foundation::Collections::IIterable<winrt::Windows::Networking::Vpn::VpnPacketBuffer>>
    {
        IVpnPacketBufferList2(std::nullptr_t = nullptr) noexcept {}
        IVpnPacketBufferList2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnPickedCredential :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnPickedCredential>
    {
        IVpnPickedCredential(std::nullptr_t = nullptr) noexcept {}
        IVpnPickedCredential(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnPlugIn :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnPlugIn>
    {
        IVpnPlugIn(std::nullptr_t = nullptr) noexcept {}
        IVpnPlugIn(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnPlugInProfile :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnPlugInProfile>,
        impl::require<winrt::Windows::Networking::Vpn::IVpnPlugInProfile, winrt::Windows::Networking::Vpn::IVpnProfile>
    {
        IVpnPlugInProfile(std::nullptr_t = nullptr) noexcept {}
        IVpnPlugInProfile(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnPlugInProfile2 :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnPlugInProfile2>,
        impl::require<winrt::Windows::Networking::Vpn::IVpnPlugInProfile2, winrt::Windows::Networking::Vpn::IVpnProfile>
    {
        IVpnPlugInProfile2(std::nullptr_t = nullptr) noexcept {}
        IVpnPlugInProfile2(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnProfile :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnProfile>
    {
        IVpnProfile(std::nullptr_t = nullptr) noexcept {}
        IVpnProfile(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnRoute :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnRoute>
    {
        IVpnRoute(std::nullptr_t = nullptr) noexcept {}
        IVpnRoute(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnRouteAssignment :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnRouteAssignment>
    {
        IVpnRouteAssignment(std::nullptr_t = nullptr) noexcept {}
        IVpnRouteAssignment(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnRouteFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnRouteFactory>
    {
        IVpnRouteFactory(std::nullptr_t = nullptr) noexcept {}
        IVpnRouteFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnSystemHealth :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnSystemHealth>
    {
        IVpnSystemHealth(std::nullptr_t = nullptr) noexcept {}
        IVpnSystemHealth(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnTrafficFilter :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnTrafficFilter>
    {
        IVpnTrafficFilter(std::nullptr_t = nullptr) noexcept {}
        IVpnTrafficFilter(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnTrafficFilterAssignment :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnTrafficFilterAssignment>
    {
        IVpnTrafficFilterAssignment(std::nullptr_t = nullptr) noexcept {}
        IVpnTrafficFilterAssignment(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
    struct __declspec(empty_bases) IVpnTrafficFilterFactory :
        winrt::Windows::Foundation::IInspectable,
        impl::consume_t<IVpnTrafficFilterFactory>
    {
        IVpnTrafficFilterFactory(std::nullptr_t = nullptr) noexcept {}
        IVpnTrafficFilterFactory(void* ptr, take_ownership_from_abi_t) noexcept : winrt::Windows::Foundation::IInspectable(ptr, take_ownership_from_abi) {}
    };
}
#endif
